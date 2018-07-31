// Copyright (c) 2018 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestNewNetmonErrorWrongFamilyType(t *testing.T) {
	netlinkFamily = -1

	n, err := newNetmon(netmonParams{})
	assert.NotNil(t, err)
	assert.Nil(t, n)
}

func TestNewNetmonErrorWrongFamilyType(t *testing.T) {
	n, err := newNetmon(netmonParams{})
	assert.NotNil(t, err)
	assert.Nil(t, n)
}
