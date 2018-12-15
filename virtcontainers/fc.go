// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package virtcontainers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"strconv"
	"strings"
	"sync"
	"time"

	opentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"

	"github.com/kata-containers/runtime/virtcontainers/device/config"

	"net"
	"net/http"

	"github.com/go-openapi/strfmt"

	"github.com/firecracker-microvm/firecracker-go-sdk/client"
	models "github.com/firecracker-microvm/firecracker-go-sdk/client/models"
	ops "github.com/firecracker-microvm/firecracker-go-sdk/client/operations"
	httptransport "github.com/go-openapi/runtime/client"
)

type vmmState uint8

const (
	notReady vmmState = iota
	apiReady
	vmReady
)

const (
	//FcTimeout is the maximum amount of time in seconds to wait for the VMM to respond
	FcTimeout  = 10
	fireSocket = "firecracker.sock"
)

func (s vmmState) String() string {
	switch s {
	case notReady:
		return "not ready"
	case apiReady:
		return "FC API ready"
	case vmReady:
		return "VM ready"
	}

	return ""
}

type firecrackerState struct {
	sync.RWMutex
	state vmmState
}

func (s *firecrackerState) set(state vmmState) {
	s.Lock()
	defer s.Unlock()

	s.state = state
}

// This indicates the number of block devices that can be attached to the
// firecracker guest VM.
// We attach a pool of placeholder drives before the guest has started, and then
// patch the replace placeholder drives with drives with actual contents.
const fcDiskPoolSize = 8

// firecracker is an Hypervisor interface implementation for the firecracker hypervisor.
type firecracker struct {
	id    string //Unique ID per pod. Normally maps to the sandbox id
	state firecrackerState

	firecrackerd *exec.Cmd           //Tracks the firecracker process itself
	client       *client.Firecracker //Tracks the current active connection
	socketPath   string

	storage        resourceStorage
	config         HypervisorConfig
	pendingDevices []firecrackerDevice // Devices to be added when the FC API is ready
	ctx            context.Context
}

type firecrackerDevice struct {
	dev     interface{}
	devType deviceType
}

// Logger returns a logrus logger appropriate for logging firecracker  messages
func (fc *firecracker) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "firecracker")
}

func (fc *firecracker) trace(name string) (opentracing.Span, context.Context) {
	if fc.ctx == nil {
		fc.Logger().WithField("type", "bug").Error("trace called before context set")
		fc.ctx = context.Background()
	}

	span, ctx := opentracing.StartSpanFromContext(fc.ctx, name)

	span.SetTag("subsystem", "hypervisor")
	span.SetTag("type", "firecracker")

	return span, ctx
}

//
// init: initialize the firecracker hypervisor's structure. Doesn't
//  actually do anything with firecracker itself, rather it just parses
//  through and provides necessary details for its structs...
//
func (fc *firecracker) init(ctx context.Context, id string, hypervisorConfig *HypervisorConfig, storage resourceStorage) error {
	fc.ctx = ctx

	span, _ := fc.trace("init")
	defer span.Finish()

	//TODO: check validity of the hypervisor config provided
	fc.id = id
	fc.socketPath = filepath.Join(runStoragePath, fc.id, "firecracker.sock")
	fc.storage = storage
	fc.config = *hypervisorConfig
	fc.state.set(notReady)

	return nil
}

// for firecracker this call isn't necessary
func (fc *firecracker) createSandbox() error {
	span, _ := fc.trace("createSandbox")
	defer span.Finish()

	return nil
}

func (fc *firecracker) newFireClient() *client.Firecracker {
	span, _ := fc.trace("newFireClient")
	defer span.Finish()
	httpClient := client.NewHTTPClient(strfmt.NewFormats())

	socketTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, path string) (net.Conn, error) {
			addr, err := net.ResolveUnixAddr("unix", fc.socketPath)
			if err != nil {
				return nil, err
			}

			return net.DialUnix("unix", nil, addr)
		},
	}

	transport := httptransport.New(client.DefaultHost, client.DefaultBasePath, client.DefaultSchemes)
	transport.Transport = socketTransport
	httpClient.SetTransport(transport)

	return httpClient
}

// waitVMM will wait for timeout seconds for the VMM to be up and running.
// This does not mean that the VM is up and running. It only indicates that the VMM is up and
// running and able to handle commands to setup and launch a VM
func (fc *firecracker) waitVMM(timeout int) error {
	span, _ := fc.trace("waitVMM")
	defer span.Finish()

	if timeout < 0 {
		return fmt.Errorf("Invalid timeout %ds", timeout)
	}

	timeStart := time.Now()
	for {
		_, err := fc.client.Operations.DescribeInstance(nil)
		if err == nil {
			return nil
		}

		if int(time.Now().Sub(timeStart).Seconds()) > timeout {
			return fmt.Errorf("Failed to connect to firecrackerinstance (timeout %ds): %v", timeout, err)
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}
	return nil
}

func (fc *firecracker) fcInit(timeout int) error {
	span, _ := fc.trace("fcInit")
	defer span.Finish()

	args := []string{"--api-sock", fc.socketPath}

	cmd := exec.Command(fc.config.HypervisorPath, args...)
	err := cmd.Start()
	if err != nil {
		fc.Logger().WithField("Error starting firecracker", err).Debug()
		os.Exit(1)
	}

	fc.firecrackerd = cmd
	fc.client = fc.newFireClient()

	err = fc.waitVMM(timeout)

	if err != nil {
		fc.Logger().WithField("fcInit failed:", err).Debug()
		return err
	}

	fc.state.set(apiReady)

	return nil
}

func (fc *firecracker) fcSetBootSource(path, params string) error {
	span, _ := fc.trace("fcSetBootSource")
	defer span.Finish()
	fc.Logger().WithField("kernel path:", path).Debug()
	fc.Logger().WithField("kernel params:", params).Debug()

	bootSrcParams := ops.NewPutGuestBootSourceParams()
	src := &models.BootSource{
		KernelImagePath: &path,
		BootArgs:        params,
	}
	bootSrcParams.SetBody(src)

	_, err := fc.client.Operations.PutGuestBootSource(bootSrcParams)
	if err != nil {
		fc.Logger().WithField("fcSetBootSource failed:", err).Debug()
		return err
	}

	return nil
}

func (fc *firecracker) fcSetVMRootfs(path string) error {
	span, _ := fc.trace("fcSetVMRootfs")
	defer span.Finish()
	fc.Logger().WithField("VM rootfs path:", path).Debug()

	driveID := "rootfs"
	driveParams := ops.NewPutGuestDriveByIDParams()
	driveParams.SetDriveID(driveID)
	isReadOnly := false
	isRootDevice := true
	drive := &models.Drive{
		DriveID:      &driveID,
		IsReadOnly:   &isReadOnly,
		IsRootDevice: &isRootDevice,
		PathOnHost:   &path,
	}
	driveParams.SetBody(drive)
	_, err := fc.client.Operations.PutGuestDriveByID(driveParams)
	if err != nil {
		fc.Logger().WithField("fcSetVMRootfs failed:", err).Debug()
		return err
	}

	return nil
}

func (fc *firecracker) fcStartVM() error {
	fc.Logger().Info("start firecracker virtual machine")
	span, _ := fc.trace("fcStartVM")
	defer span.Finish()

	fc.Logger().Info("Starting VM")

	fc.client = fc.newFireClient()

	actionParams := ops.NewCreateSyncActionParams()
	actionInfo := &models.InstanceActionInfo{
		ActionType: "InstanceStart",
	}
	actionParams.SetInfo(actionInfo)
	_, err := fc.client.Operations.CreateSyncAction(actionParams)
	if err != nil {
		fc.Logger().WithField("start firecracker virtual machine failed:", err).Debug()
		return err
	}

	fc.state.set(vmReady)

	return nil
}

// startSandbox will start the hypervisor for the given sandbox.
// In the context of firecracker, this will start the hypervisor,
// for configuration, but not yet start the actual virtual machine
func (fc *firecracker) startSandbox() error {
	span, _ := fc.trace("startSandbox")
	defer span.Finish()

	fc.fcInit(FcTimeout)

	kernelPath, err := fc.config.KernelAssetPath()
	if err != nil {
		return err
	}

	strParams := SerializeParams(fc.config.KernelParams, "=")
	formattedParams := strings.Join(strParams, " ")

	fc.fcSetBootSource(kernelPath, formattedParams)

	image, err := fc.config.InitrdAssetPath()
	if err != nil {
		return err
	}

	if image == "" {
		image, err = fc.config.ImageAssetPath()
		if err != nil {
			return err
		}
		//how to handle this error...
	}

	fc.fcSetVMRootfs(image)
	fc.createDiskPool()

	for _, d := range fc.pendingDevices {
		if err = fc.addDevice(d.dev, d.devType); err != nil {
			return err
		}
	}

	return fc.fcStartVM()
}

func (fc *firecracker) createDiskPool() error {
	span, _ := fc.trace("createDiskPool")
	defer span.Finish()

	for i := 0; i < fcDiskPoolSize; i++ {
		driveID := "drive-" + strconv.Itoa(i)
		driveParams := ops.NewPutGuestDriveByIDParams()
		driveParams.SetDriveID(driveID)
		isReadOnly := false
		isRootDevice := false

		// Create a temporary file as a placeholder backend for the drive
		hostPath, err := fc.storage.createSandboxTempFile(fc.id)
		if err != nil {
			return err
		}

		drive := &models.Drive{
			DriveID:      &driveID,
			IsReadOnly:   &isReadOnly,
			IsRootDevice: &isRootDevice,
			PathOnHost:   &hostPath,
		}
		driveParams.SetBody(drive)
		_, err = fc.client.Operations.PutGuestDriveByID(driveParams)
		if err != nil {
			fc.Logger().WithField("fcSetVMRootfs failed:", err).Debug()
			return err
		}
	}

	return nil
}

// waitSandbox will wait for the Sandbox's VM to be up and running.
func (fc *firecracker) waitSandbox(timeout int) error {
	span, _ := fc.trace("waitSandbox")
	defer span.Finish()

	return fc.waitVMM(timeout)
}

// stopSandbox will stop the Sandbox's VM.
func (fc *firecracker) stopSandbox() error {
	span, _ := fc.trace("stopSandbox")
	defer span.Finish()

	fc.Logger().Info("Stopping Sandbox")

	actionParams := ops.NewCreateSyncActionParams()
	actionInfo := &models.InstanceActionInfo{
		ActionType: "InstanceHalt",
	}
	actionParams.SetInfo(actionInfo)
	_, err := fc.client.Operations.CreateSyncAction(actionParams)
	if err != nil {
		fc.Logger().WithField("stopSandbox failed:", err).Debug()
		return err
	}

	return nil
}

func (fc *firecracker) pauseSandbox() error {
	return nil
}

func (fc *firecracker) saveSandbox() error {
	return nil
}

func (fc *firecracker) resumeSandbox() error {
	return nil
}

func (fc *firecracker) fcAddVsock(vs kataVSOCK) error {
	span, _ := fc.trace("fcAddVsock")
	defer span.Finish()

	vsockParams := ops.NewPutGuestVsockByIDParams()
	vsockID := "root"
	vsock := &models.Vsock{
		GuestCid: int64(vs.contextID),
		ID:       &vsockID,
	}
	vsockParams.SetID(vsockID)
	vsockParams.SetBody(vsock)
	_, _, err := fc.client.Operations.PutGuestVsockByID(vsockParams)
	if err != nil {
		fc.Logger().WithField("fcAddVsock:", err).Debug()
		return err
	}
	//Still racy. There is no way to send an fd to the firecracker
	//REST API. We could release this just before we start the instance
	//but even that will not eliminate the race
	vs.vhostFd.Close()
	return nil
}

func (fc *firecracker) fcAddNetDevice(endpoint Endpoint) error {
	span, _ := fc.trace("fcAddNetDevice")
	defer span.Finish()

	cfg := ops.NewPutGuestNetworkInterfaceByIDParams()
	ifaceID := endpoint.Name()
	ifaceCfg := &models.NetworkInterface{
		AllowMmdsRequests: false,
		GuestMac:          endpoint.HardwareAddr(),
		IfaceID:           &ifaceID,
		HostDevName:       endpoint.NetworkPair().TapInterface.TAPIface.Name,
		State:             "Attached",
	}
	cfg.SetBody(ifaceCfg)
	cfg.SetIfaceID(ifaceID)
	_, err := fc.client.Operations.PutGuestNetworkInterfaceByID(cfg)
	if err != nil {
		fc.Logger().WithField("fcAddNetDevice failed:", err).Debug()
		return err
	}

	return nil
}

func (fc *firecracker) fcAddBlockDrive(drive config.BlockDrive) error {
	span, _ := fc.trace("fcAddBlockDrive")
	defer span.Finish()

	driveID := drive.ID
	driveParams := ops.NewPutGuestDriveByIDParams()
	driveParams.SetDriveID(driveID)
	isReadOnly := false
	isRootDevice := false
	driveFc := &models.Drive{
		DriveID:      &driveID,
		IsReadOnly:   &isReadOnly,
		IsRootDevice: &isRootDevice,
		PathOnHost:   &drive.File,
	}
	driveParams.SetBody(driveFc)
	_, err := fc.client.Operations.PutGuestDriveByID(driveParams)
	if err != nil {
		fc.Logger().WithField("fcAddBlockDrive failed:", err).Debug()
		return err
	}

	return nil
}

// Firecracker supports replacing the host drive used once the VM has booted up
func (fc *firecracker) fcUpdateBlockDrive(drive config.BlockDrive) error {
	span, _ := fc.trace("fcUpdateBlockDrive")
	defer span.Finish()

	// Use the global block index as an index into the pool of the devices
	// created for firecracker.
	driveID := "drive-" + strconv.Itoa(drive.Index)
	driveParams := ops.NewPatchGuestDriveByIDParams()
	driveParams.SetDriveID(driveID)

	driveFc := &models.PartialDrive{
		DriveID:    &driveID,
		PathOnHost: &drive.File, //This is the only property that can be modified
	}
	driveParams.SetBody(driveFc)
	_, err := fc.client.Operations.PatchGuestDriveByID(driveParams)
	if err != nil {
		fc.Logger().WithField("fcUpdateBlockDrive failed:", err).Debug()
		return err
	}

	actionParams := ops.NewCreateSyncActionParams()
	actionInfo := &models.InstanceActionInfo{
		ActionType: "BlockDeviceRescan",
	}
	actionParams.SetInfo(actionInfo)
	_, err = fc.client.Operations.CreateSyncAction(actionParams)
	if err != nil {
		fc.Logger().WithField("fcUpdateBlockDrive BlockDeviceRescan failed:", err).Debug()
		return err
	}

	return nil
}

// addDevice will add extra devices to firecracker.  Limited to configure before the
// virtual machine starts.  Devices include drivers and network interfaces only.
func (fc *firecracker) addDevice(devInfo interface{}, devType deviceType) error {
	span, _ := fc.trace("addDevice")
	defer span.Finish()

	fc.state.RLock()
	defer fc.state.RUnlock()

	if fc.state.state == notReady {
		dev := firecrackerDevice{
			dev:     devInfo,
			devType: devType,
		}
		fc.Logger().Warn("FC not ready, queueing device")
		fc.pendingDevices = append(fc.pendingDevices, dev)
		return nil
	}

	fc.Logger().Info("adding a device")
	switch v := devInfo.(type) {
	case Endpoint:
		fc.Logger().Info("Adding net device")
		return fc.fcAddNetDevice(v)
	case config.BlockDrive:
		fc.Logger().Info("Adding block device")
		return fc.fcAddBlockDrive(v)
	case kataVSOCK:
		fc.Logger().Info("Adding vsock")
		return fc.fcAddVsock(v)
	default:
		fc.Logger().Warning("unknown device")
		break
	}

	return nil
}

// hotplugAddDevice not supported in Firecracker VMM
func (fc *firecracker) hotplugAddDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	span, _ := fc.trace("hotplugAddDevice")
	defer span.Finish()

	switch devType {
	case blockDev:
		//The drive placeholder has to exist prior to Update
		return nil, fc.fcUpdateBlockDrive(*devInfo.(*config.BlockDrive))
	default:
		fc.Logger().WithField("devInfo", devInfo).Warn("hotplugAddDevce: unknown device")
		fc.Logger().WithField("devType:", devType).Warn("hotplugAddDevce: unknown device")
		break
	}

	return nil, nil
}

// hotplugRemoveDevice not supported in Firecracker VMM
func (fc *firecracker) hotplugRemoveDevice(devInfo interface{}, devType deviceType) (interface{}, error) {
	return nil, fmt.Errorf("firecracker does not support hotplugRemoveDevice")
}

// getSandboxConsole builds the path of the console where we can read
// logs coming from the sandbox.
//
// we can get logs from firecracker itself; WIP on enabling.  Who needs
// logs when you're just hacking?
func (fc *firecracker) getSandboxConsole(id string) (string, error) {
	return "", nil
}

func (fc *firecracker) disconnect() {
	fc.state.set(notReady)
	return
}

// Adds all capabilities supported by firecracker implementation of hypervisor interface
func (fc *firecracker) capabilities() capabilities {
	span, _ := fc.trace("capabilities")
	defer span.Finish()
	var caps capabilities
	caps.setFsSharingUnsupported()
	caps.setBlockDeviceHotplugSupport()

	return caps
}

func (fc *firecracker) hypervisorConfig() HypervisorConfig {
	return fc.config
}

func (fc *firecracker) resizeMemory(reqMemMB uint32, memoryBlockSizeMB uint32) (uint32, error) {
	return 0, nil
}

func (fc *firecracker) resizeVCPUs(reqVCPUs uint32) (currentVCPUs uint32, newVCPUs uint32, err error) {
	return 0, 0, nil
}

// this is used to apply cgroup information on the host. not sure how necessary this
// is in the first pass.
//
// Need to see if there's an easy way to ask firecracker for thread ids associated with
// the vCPUs.  Issue opened to ask for per vCPU thread IDs:
// https://github.com/firecracker-microvm/firecracker/issues/718
func (fc *firecracker) getThreadIDs() (*threadIDs, error) {
	//TODO: this may not be exactly supported in Firecracker. Closest is cpu-template as part
	// of get /machine-config
	return nil, nil
}
