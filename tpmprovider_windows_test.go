// +build windows

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	OwnerSecretKey     = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey       = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	BadSecretKey       = "b000b000b000b000b000b000b000b000b000b000"
	CertifiedKeySecret = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
)

func createTestTpm(t *testing.T) TpmProvider {
	factory, err := NewTpmFactory()
	if err != nil {
		t.Fatal("Could not create factory")
	}

	tpm, err := factory.NewTpmProvider()
	if err != nil {
		t.Fatal("Could not create tpmprovider")
	}

	return tpm
}

func TestIsOwnedWithAuthPositive(t *testing.T) {

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	owned, err := tpm.IsOwnedWithAuth(OwnerSecretKey)
	assert.NoError(t, err)
	assert.True(t, owned)

}

func TestTpmVersion(t *testing.T) {

	tpm := createTestTpm(t)
	defer tpm.Close()

	version := tpm.Version()
	t.Logf("version is %d", version)
	assert.NotEqual(t, version, 0)
}

func TestNvRam(t *testing.T) {

	tpm := createTestTpm(t)
	defer tpm.Close()

	//ownerAuth := "Pldh0ylDEX0TnPnbcIMKlKlPSNI="
	ownerAuth := ""

	// define/read/write/delete some data in nvram
	idx := uint32(NV_IDX_ASSET_TAG)
	data, _ := hex.DecodeString("f00df00df00df00df00df00df00df00df00df00df00df00df00df00df00d")

	exists, err := tpm.NvIndexExists(idx)
	assert.NoError(t, err)

	if exists {
		err = tpm.NvRelease(ownerAuth, idx)
		if err != nil {
			t.Fatal("Could not clear nvram index")
		}
	}

	err = tpm.NvDefine(ownerAuth, idx, uint16(len(data)))
	assert.NoError(t, err)

	err = tpm.NvWrite(ownerAuth, idx, data)
	assert.NoError(t, err)

	output, err := tpm.NvRead(ownerAuth, idx)
	assert.NoError(t, err)
	assert.Equal(t, data, output)

	t.Logf("Read: %s", hex.EncodeToString(output))

	err = tpm.NvRelease(ownerAuth, idx)
	assert.NoError(t, err)
}

func TestAik(t *testing.T) {

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	aikBytes, err := tpm.GetAikBytes()
	assert.NoError(t, err)
	assert.NotNil(t, 0, aikBytes)
	assert.NotEqual(t, 0, len(aikBytes))
}

func TestGetAikNamePositive(t *testing.T) {

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	output, err := tpm.GetAikName()
	assert.NoError(t, err)
	assert.NotEqual(t, len(output), 0)

}

func TestCreatePrimaryHandlePositive(t *testing.T) {

	tpm := createTestTpm(t)
	assert.NotEqual(t, tpm, nil)
	defer tpm.Close()

	exists, err := tpm.PublicKeyExists(TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	if exists {
		err = tpm.ClearPublicKey(OwnerSecretKey, TPM_HANDLE_PRIMARY)
		if err != nil {
			t.Fatal("Could not clear public key")
		}
	}

	err = tpm.CreatePrimaryHandle(AikSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	err = tpm.ClearPublicKey(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	if err != nil {
		t.Fatal("Could not clear public key")
	}

}
