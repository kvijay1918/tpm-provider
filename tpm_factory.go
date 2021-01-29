/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import "errors"

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

var factory *linuxTpmFactory

func InitializeTpmFactory(tcti uint32, cfg string) error {
	factory = nil
	switch tcti {
	case TCTI_ABRMD:
		factory = &linuxTpmFactory{tctiType: TCTI_ABRMD}
		return nil
	case TCTI_DEVICE:
		if cfg == ""{
			factory = &linuxTpmFactory{tctiType: TCTI_ABRMD, conf: cfg}
			return nil
		} else if cfg == "/dev/tpm0" || cfg == "/dev/tpmrm0" {
			factory = &linuxTpmFactory{tctiType: TCTI_DEVICE, conf: cfg}
			return nil
		} else {
			return errors.New("Unsupported TCTI device")
		}
	case TCTI_MSSIM:
		if cfg == ""{
			cfg = "host=localhost,port=2321"
		}
		factory = &linuxTpmFactory{tctiType: TCTI_MSSIM, conf: cfg}
		return nil
	default:
		return errors.New("Unsupported TCTI type")
	}

}
