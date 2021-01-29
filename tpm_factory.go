/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import "errors"

var factory *linuxTpmFactory

var tctiOptions = map[string]uint32{"tpm2-abrmd": TCTI_ABRMD,
	"device": TCTI_DEVICE,
	"mssim":  TCTI_MSSIM}

func InitializeTpmFactory(tcti string, cfg string) error {
	factory = nil
	switch tctiOptions[tcti] {
	case TCTI_ABRMD:
		factory = &linuxTpmFactory{tctiType: TCTI_ABRMD}
		return nil
	case TCTI_DEVICE:
		if cfg == "" {
			factory = &linuxTpmFactory{tctiType: TCTI_DEVICE, conf: "/dev/tpmrm0"}
			return nil
		} else if cfg == "/dev/tpm0" || cfg == "/dev/tpmrm0" {
			factory = &linuxTpmFactory{tctiType: TCTI_DEVICE, conf: cfg}
			return nil
		} else {
			return errors.New("Unsupported TCTI device")
		}
	case TCTI_MSSIM:
		if cfg == "" {
			cfg = "host=localhost,port=2321"
		}
		factory = &linuxTpmFactory{tctiType: TCTI_MSSIM, conf: cfg}
		return nil
	default:
		return errors.New("Unsupported TCTI type")
	}

}
