/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	OwnerSecretKey     = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey       = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	BadSecretKey       = "b000b000b000b000b000b000b000b000b000b000"
	CertifiedKeySecret = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
)

func createSimulatorAndFactory(t *testing.T) TpmSimulator {

	tpmSimulator := NewTpmSimulator()
	err := tpmSimulator.Start()
	if err != nil {
		assert.FailNowf(t, "Could not start TPM Simulator", "%s", err)
	}

	InitializeTpmFactory("mssim", "host=localhost,port=2321")

	return tpmSimulator
}

// Creates a new instance of the TPM simulator and TpmProvider.  The simulator
// is not provisioned with an owner secret or EK Certificate (see createProvisionedSimulatorAndProvider).
func createSimulatorAndProvider(t *testing.T) (TpmSimulator, TpmProvider) {

	tpmSimulator := createSimulatorAndFactory(t)

	tpmProvider, err := NewTpmProvider()
	if err != nil {
		assert.FailNowf(t, "Could not create tpm provider", "%s", err)
	}

	err = tpmProvider.Create()
	if err != nil {
		assert.FailNowf(t, "Could not create TPM", "%s", err)
	}

	return tpmSimulator, tpmProvider
}

// Creates a new simulator (un-provisioned) and then takes ownership and
// provisions an EK Certificate.
func createProvisionedSimulatorAndProvider(t *testing.T) (TpmSimulator, TpmProvider) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)

	err := tpmProvider.TakeOwnership(OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// Creating an AIK requires an EK which requires an EK Certificate, provision one in the
	// tpm simulator...
	err = tpmSimulator.ProvisionEkCertificate(tpmProvider, OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "Could not provision the EK Certificate in the TPM Simulator", "%s", err)
	}

	return tpmSimulator, tpmProvider
}

func TestTpmFactory(t *testing.T) {

	tpmSimulator := NewTpmSimulator()
	err := tpmSimulator.Start()
	if err != nil {
		assert.FailNowf(t, "Could not start TPM Simulator", "%s", err)
	}

	defer tpmSimulator.Stop()

	InitializeTpmFactory("mssim", "host=localhost,port=2321")

	for i := 1; i < 5; i++ {
		t.Log("creating tpm...")

		tpmProvider, err := NewTpmProvider()
		if err != nil {
			assert.FailNowf(t, "Could not create TPM", "%s", err)
		}

		err = tpmProvider.Create()
		if err != nil {
			assert.FailNowf(t, "Could not create TPM", "%s", err)
		}
		_, err = tpmProvider.IsOwnedWithAuth(OwnerSecretKey)
		if err != nil {
			assert.FailNowf(t, "", "%s", err)
		}

		tpmProvider.Close()
	}
}

func TestTpmVersion(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	version := tpmProvider.Version()
	assert.NotEqual(t, version, 0)
}

func TestTakeOwnershipWithValidSecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)
}

func TestTakeOwnershipWithEmptySecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership("")
	assert.Error(t, err)
}

func TestTakeOwnershipWithInvalidSecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership("shouldbe40charsofhex")
	assert.Error(t, err)
}

func TestIsOwnedWithAuthPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	owned, err := tpmProvider.IsOwnedWithAuth(OwnerSecretKey)
	assert.NoError(t, err)
	assert.True(t, owned)
}

func TestIsOwnedWithAuthNegative(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	owned, err := tpmProvider.IsOwnedWithAuth(BadSecretKey)
	assert.NoError(t, err)
	assert.False(t, owned)
}

func TestCreateAikPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	isValidEk, err := tpmProvider.IsValidEk(OwnerSecretKey, TPM_HANDLE_EK, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		assert.FailNowf(t, "Error validating EK", "%s", err)
	}

	if !isValidEk {
		assert.FailNowf(t, "The EK is not valid", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)
}

func TestGetAikBytesPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err:= tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	output, err := tpmProvider.GetAikBytes()
	assert.NoError(t, err)
	assert.NotEqual(t, len(output), 0)
}

func TestGetAikNamePositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	output, err := tpmProvider.GetAikName()
	assert.NoError(t, err)
	assert.NotEqual(t, len(output), 0)
}

func TestActivateCredentialInvalidOwnerSecret(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	credentialBytes := make([]byte, 20)
	secretBytes := make([]byte, 20)

	// just testing the secret key at this time...
	_, err = tpmProvider.ActivateCredential(BadSecretKey, AikSecretKey, credentialBytes, secretBytes)
	assert.Error(t, err)
}

func TestTpmQuotePositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// Test quote
	nonce, _ := base64.StdEncoding.DecodeString("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=")
	pcrs := []int{0, 1, 2, 3, 18, 19, 22}
	pcrBanks := []string{"SHA1", "SHA256"}
	quoteBytes, err := tpmProvider.GetTpmQuote(AikSecretKey, nonce, pcrBanks, pcrs)
	assert.NoError(t, err)
	assert.NotEqual(t, len(quoteBytes), 0)
}

// Similar to...
// tpm2_nvdefine -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -s 1024 -t 0x2000a # (ownerread|ownerwrite|policywrite)
// tpm2_nvwrite -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 /tmp/quote.bin
// tpm2_nvread -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 -f /tmp/quote_nv.bin
func TestNvRamPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// take ownership
	err := tpmProvider.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	// define/read/write/delete some data in nvram
	idx := uint32(NV_IDX_ASSET_TAG)
	data := make([]byte, 1527) // just test something over 1024 bytes which seems to be an issue with physical tpms

	err = tpmProvider.NvDefine(OwnerSecretKey, idx, uint16(len(data)))
	assert.NoError(t, err)

	err = tpmProvider.NvWrite(OwnerSecretKey, idx, data)
	assert.NoError(t, err)

	output, err := tpmProvider.NvRead(OwnerSecretKey, idx)
	assert.NoError(t, err)
	assert.Equal(t, data, output)

	err = tpmProvider.NvRelease(OwnerSecretKey, idx)
	assert.NoError(t, err)
}

func TestCreatePrimaryHandlePositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)
}

func TestSigningPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the primary key used for creating the singing key...
	err = tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	signingKey, err := tpmProvider.CreateSigningKey(CertifiedKeySecret, AikSecretKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signingKey.PublicKey)
	assert.NotEmpty(t, signingKey.PrivateKey)
	assert.NotEmpty(t, signingKey.KeySignature)
	assert.NotEmpty(t, signingKey.KeyAttestation)
	assert.NotEmpty(t, signingKey.KeyName)
	assert.Equal(t, signingKey.Usage, Signing)
	assert.Equal(t, signingKey.Version, V20)

	// just hash some bytes (in this case the aik secret key) and make sure
	// no error occurs and bytes are returned
	hashToSign := make([]byte, 32, 32)
	signedBytes, err := tpmProvider.Sign(signingKey, CertifiedKeySecret, hashToSign)
	assert.NoError(t, err)
	assert.NotEqual(t, len(signedBytes), 0)
}

func TestBindingPositive(t *testing.T) {

	tpmSimulator, tpmProvider := createProvisionedSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the primary key used for creating the singing key...
	err = tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	bindingKey, err := tpmProvider.CreateBindingKey(CertifiedKeySecret, AikSecretKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, bindingKey.PublicKey)
	assert.NotEmpty(t, bindingKey.PrivateKey)
	assert.NotEmpty(t, bindingKey.KeySignature)
	assert.NotEmpty(t, bindingKey.KeyAttestation)
	assert.NotEmpty(t, bindingKey.KeyName)
	assert.Equal(t, bindingKey.Usage, Binding)
	assert.Equal(t, bindingKey.Version, V20)

	// just hash some bytes (in this case the aik secret key) and make sure
	// no error occurs and bytes are returned
	// tpmprovider.sign uses rsa/sha256, hash needs be 32 bytes long
	// encryptedBytes := make([]byte, 32, 32)
	// decryptedBytes, err := tpmProvider.Unbind(bindingKey, CertifiedKeySecret, encryptedBytes)
	// assert.NoError(t, err)
	// assert.NotEqual(t, len(decryptedBytes), 0)
}

func TestMultiThreadedQuote(t *testing.T) {

	// This unit test is being skipped since it because deadlock occurs when the TSS2 is
	// configured to use the mssim tcti directory.  The test will pass if
	// it is run against tpm-abrmd via NewTpmFactory().
	t.Skip()

	var wg sync.WaitGroup

	InitializeTpmFactory("mssim", "host=localhost,port=2321")

	// Provision the TPM to support quotes...
	tpmProvider, err := NewTpmProvider()
	if err != nil {
		assert.FailNowf(t, "Could not create TPM factory", "%s", err)
	}

	err = tpmProvider.Create()
	if err != nil {
		assert.FailNowf(t, "Could not create TPM", "%s", err)
	}

	err = tpmProvider.TakeOwnership(OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the EK and AIK
	err = tpmProvider.CreateEk(OwnerSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, AikSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// close the tpmprovider that did provisioning (this isn't multithreaded in the real world)
	tpmProvider.Close()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(threadNum int) {
			defer wg.Done()

			// generate some sleep somewhere under a second
			sleep, err := rand.Int(rand.Reader, big.NewInt(1000))
			assert.NoError(t, err)
			fmt.Printf("Thread[%d]: Sleeping for %d milliseconds\n", threadNum, sleep)
			time.Sleep(time.Duration(sleep.Int64()))

			tpm, err := NewTpmProvider()
			assert.NoError(t, err)
			defer tpm.Close()

			err = tpm.Create()
			if err != nil {
				assert.FailNowf(t, "Could not create TPM", "%s", err)
			}

			nonce, _ := base64.StdEncoding.DecodeString("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=")
			pcrs := []int{0, 1, 2, 3, 18, 19, 22}
			pcrBanks := []string{"SHA1", "SHA256"}

			fmt.Printf("Thread[%d][%s]: Starting tpm quote\n", threadNum, time.Now().String())
			quoteBytes, err := tpm.GetTpmQuote(AikSecretKey, nonce, pcrBanks, pcrs)
			assert.NoError(t, err)
			assert.NotEqual(t, len(quoteBytes), 0)
			fmt.Printf("Thread[%d][%s]: Successfully completed tpm quote\n", threadNum, time.Now().String())
		}(i)
	}

	wg.Wait()
}
