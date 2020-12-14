// +build !unit_test

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import (
	"errors"
	"runtime"
)

//
// Creates the default TpmFactory that currently uses TSS2 and 'abrmd'.
//
func NewTpmFactory() (TpmFactory, error) {

	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType: TCTI_ABRMD}, nil
	} else {
		return nil, errors.New("Unsupported tpm factory platform " + runtime.GOOS)
	}
}

func NewTpmDeviceFactory() (TpmFactory, error) {

	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType: TCTI_DEVICE}, nil
	} else {
		return nil, errors.New("Unsupported tpm factory platform " + runtime.GOOS)
	}
}
