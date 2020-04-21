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
// This interface is responsible for creating instances of TpmProvider.  Generally,
// it provides a 'unit of work' model where consumers create a TpmProvider to interact
// with the physical TPM and then completes that work via TpmProvider.Close().
// In this fashion, long lived services (ex. go-trust-agent http) can retain a reference
// to the TpmFactory and create instances as needed.  This also facilitates unit testing
// and mocks.
//
type TpmFactory interface {
	NewTpmProvider() (TpmProvider, error)
}

//
// Creates the default TpmFactory that currently uses TSS2 and 'abrmd'.
//
func NewTpmFactory() (TpmFactory, error) {
	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType : TCTI_ABRMD}, nil
	} else {
		return nil, errors.New("Unsuportted tpm factory platform " + runtime.GOOS)
	}
}

func NewTpmDeviceFactory() (TpmFactory, error) {
	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType : TCTI_DEVICE}, nil
	} else {
		return nil, errors.New("Unsuportted tpm factory platform " + runtime.GOOS)
	}
}
