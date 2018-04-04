/*
 * This file is part of kata-runtime.
 *
 * Copyright (C) 2018 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <syslog.h>
#include <getopt.h>

#define PROGRAM_NAME "netns-watcher"

bool debug = false;

struct watcher_params {
	char *pod_id;
	char *runtime_path;
	char *netns_path;
};

/*
 * Print program usage.
 */
void print_usage(void) {
        printf("Usage: %s [options]\n\n", PROGRAM_NAME);
	printf(" -d, --debug        Enable debug output\n");
	printf(" -h, --help         Display usage\n");
	printf(" -n, --netns-path   Network namespace path (required)\n");
        printf(" -p, --pod-id       Pod ID (required)\n");
	printf(" -r, --runtime-path Runtime path (required)\n");
        printf(" -v, --version      Show version\n");
        printf("\n");
}

/*
 * Print version information.
 */
void print_version(void) {
	printf("%s v0.1\n", PROGRAM_NAME);
}

/* 
 * Validate the parameters and fill the appropriate structure.
 *
 * pod-id: Pod identifier related to the network namespace this watcher
 * has to listen to.
 * runtime-path: Runtime path is needed to call into it whenever a
 * change in the network namespace is detected.
 * netns-path: Network namespace path that needs to be monitored.
 *
 * It returns 0 if the parameters are valid, with a watcher_params structure
 * properly filled. Otherwise, it returns -1 with a null watcher_params
 * structure.
 */
int valid_params(int argc, const char **argv, struct watcher_params *params) {
	struct option prog_opts[] = {
		{"debug", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"netns-path", required_argument, 0, 'n'},
		{"pod-id", required_argument, 0, 'p'},
		{"runtime-path", required_argument, 0, 'r'},
		{"version", no_argument, 0, 'v'},
		{ 0, 0, 0, 0},
	};

	int c;
	while ((c = getopt_long(argc, (char **)argv, "dhn:p:r:v", prog_opts, NULL)) != -1) {
		switch (c) {
			case 'd':
				debug = true;
				break;
			case 'h':
				print_usage();
				exit(EXIT_SUCCESS);
			case 'n':
				params->netns_path = strdup(optarg);
				break;
			case 'p':
				params->pod_id = strdup(optarg);
				break;
			case 'r':
				params->runtime_path = strdup(optarg);
				break;
			case 'v':
				print_version();
				exit(EXIT_SUCCESS);
			default:
				print_usage();
				exit(EXIT_FAILURE);
		}
	}

	if (!params->netns_path) {
		printf("Missing network namespace path\n");
		return -1;
		
	}

	if (!params->pod_id) {
		printf("Missing pod ID\n");
		return -1;
	}

	if (!params->runtime_path) {
		printf("Missing runtime path\n");
		return -1;
	}

	return 0;
}

/* 
 * Enter the network namespace.
 *
 * Entering the provided network namespace since the point of this binary is
 * to monitor any network change happening inside a specific network namespace.
 */
int enter_netns(const char *netns_path) {
	int fd;

	fd = open(netns_path, O_RDONLY);
	if (fd == -1) {
		printf("Failed opening network ns %s: %s\n",
		       netns_path, strerror(errno));
	}

	if (setns(fd, 0) == -1) {
		printf("Failed to join network ns %s: %s\n",
		       netns_path, strerror(errno));
	}

/*
	char *cmd = "/sbin/ifconfig";
	char *argv[2];
	argv[0] = "/sbin/ifconfig";
	argv[1] = NULL;

	execvp(cmd, argv); 
*/
	return 0;
}

/* 
 * Monitor the network and call into the runtime to update the network of
 * the pod.
 *
 * The netlink socket is going to be listened to detect any change that could
 * happen to the network of the current network namespace.
 * As soon as a change gets detected, the runtime binary will be called with
 * the appropriate options to reflect the network change.
 */
int monitor_netns(const char *pod_id, const char* runtime_path) {
	return 0;
}

int main(int argc, char **argv) {
	int ret;

	struct watcher_params params = {
		.netns_path   = NULL,
		.pod_id       = NULL,
		.runtime_path = NULL,
	};

	/* Validate parameters */
	ret = valid_params(argc, (const char**)argv, &params);
	if (ret) {
		return ret;
	}

	/* Enter network namespace */
	ret = enter_netns((const char*)params.netns_path);
	if (ret) {
		return ret;
	}

	/* Monitor the network */
	ret = monitor_netns((const char*)params.pod_id,
			    (const char*)params.runtime_path);
	if (ret) {
		return ret;
	}

	return 0;
}
