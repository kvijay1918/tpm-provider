// +build linux

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
	"time"
)

const (
	OwnerSecretKey     = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	AikSecretKey       = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	BadSecretKey       = "b000b000b000b000b000b000b000b000b000b000"
	CertifiedKeySecret = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
)

func createTestTpm(t *testing.T) TpmProvider {
	tpmFactory, err := NewTpmFactory()
	if err != nil {
		t.Fatal(err)
	}

	tpmProvider, err := tpmFactory.NewTpmProvider()
	if err != nil {
		t.Fatal(err)
	}

	return tpmProvider
}

// function used to debug simulator class
func XXXTestSimulator2(t *testing.T) {

	for i :=0; i < 20; i++ {
		fmt.Printf("[[%d]]\n", i)
		simulator := GetTpmSimulator(t)
		simulator.Start()
	
		tpm := createTestTpm(t)
		_ = tpm.TakeOwnership(OwnerSecretKey)
		tpm.Close()
	
		simulator.Stop()
	}
}

func TestTpmVersion(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	version := tpm.Version()
	assert.NotEqual(t, version, 0)

	simulator.Stop()
}

func TestTakeOwnershipWithValidSecretKey(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	simulator.Stop()
}

func TestTakeOwnershipWithEmptySecretKey(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership("")
	assert.Error(t, err)

	simulator.Stop()
}

func TestTakeOwnershipWithInvalidSecretKey(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership("shouldbe40charsofhex")
	assert.Error(t, err)

	simulator.Stop()
}

func TestIsOwnedWithAuthPositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	owned, err := tpm.IsOwnedWithAuth(OwnerSecretKey)
	assert.NoError(t, err)
	assert.True(t, owned)

	simulator.Stop()
}

func TestIsOwnedWithAuthNegative(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	owned, err := tpm.IsOwnedWithAuth(BadSecretKey)
	assert.NoError(t, err)
	assert.False(t, owned)

	simulator.Stop()
}

func TestCreateAikPositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	simulator.Stop()
}

func TestGetAikBytesPositive(t *testing.T) {
	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	output, err := tpm.GetAikBytes()
	assert.NoError(t, err)
	assert.NotEqual(t, len(output), 0)

	simulator.Stop()
}

func TestGetAikNamePositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	output, err := tpm.GetAikName()
	assert.NoError(t, err)
	assert.NotEqual(t, len(output), 0)

	simulator.Stop()
}

func TestActivateCredentialInvalidOwnerSecret(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	credentialBytes := make([]byte, 20)
	secretBytes := make([]byte, 20)

	// just testing the secret key at this time...
	_, err = tpm.ActivateCredential(BadSecretKey, AikSecretKey, credentialBytes, secretBytes)
	assert.Error(t, err)

	simulator.Stop()
}

func TestTpmQuotePositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	assert.NotEqual(t, tpm, nil)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	// create an aik in the tpm
	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	nonce, _ := base64.StdEncoding.DecodeString("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=")
	pcrs := []int{0, 1, 2, 3, 18, 19, 22}
	pcrBanks := []string{"SHA1", "SHA256"}
	quoteBytes, err := tpm.GetTpmQuote(AikSecretKey, nonce, pcrBanks, pcrs)
	assert.NoError(t, err)
	assert.NotEqual(t, len(quoteBytes), 0)

	simulator.Stop()
}

// Similar to...
// tpm2_nvdefine -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -s 1024 -t 0x2000a # (ownerread|ownerwrite|policywrite)
// tpm2_nvwrite -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 /tmp/quote.bin
// tpm2_nvread -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 -f /tmp/quote_nv.bin
func TestNvRamPositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	assert.NotEqual(t, tpm, nil)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	// define/read/write/delete some data in nvram
	idx := uint32(NV_IDX_ASSET_TAG)
	data, _ := hex.DecodeString("f00df00df00df00df00df00df00df00df00df00df00df00df00df00df00d")

	err = tpm.NvDefine(OwnerSecretKey, idx, uint16(len(data)))
	assert.NoError(t, err)

	err = tpm.NvWrite(OwnerSecretKey, idx, data)
	assert.NoError(t, err)

	output, err := tpm.NvRead(OwnerSecretKey, idx)
	assert.NoError(t, err)
	assert.Equal(t, data, output)

	err = tpm.NvRelease(OwnerSecretKey, idx)
	assert.NoError(t, err)

	simulator.Stop()
}

// CreatePrimaryHandle(ownerSecretKey string, handle uint32) error
func TestCreatePrimaryHandlePositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	assert.NotEqual(t, tpm, nil)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	simulator.Stop()
}

func TestSigningPositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	// create the primary key used for creating the singing key...
	err = tpm.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	signingKey, err := tpm.CreateSigningKey(CertifiedKeySecret, AikSecretKey)
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
	signedBytes, err := tpm.Sign(signingKey, CertifiedKeySecret, hashToSign)
	assert.NoError(t, err)
	assert.NotEqual(t, len(signedBytes), 0)

	simulator.Stop()
}

func TestBindingPositive(t *testing.T) {

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	// create the primary key used for creating the singing key...
	err = tpm.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	assert.NoError(t, err)

	bindingKey, err := tpm.CreateBindingKey(CertifiedKeySecret, AikSecretKey)
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
	// decryptedBytes, err := tpm.Unbind(bindingKey, CertifiedKeySecret, encryptedBytes)
	// assert.NoError(t, err)
	// assert.NotEqual(t, len(decryptedBytes), 0)

	simulator.Stop()
}

// spawns multiple quote threads
func TestMultiThreadedQuote(t *testing.T) {

	rand.Seed(43)
	var wg sync.WaitGroup

	simulator := GetTpmSimulator(t)
	simulator.Start()

	tpm := createTestTpm(t)
	assert.NotEqual(t, tpm, nil)
	defer tpm.Close()

	// take ownership
	err := tpm.TakeOwnership(OwnerSecretKey)
	assert.NoError(t, err)

	// create an aik in the tpm
	err = tpm.CreateAik(OwnerSecretKey, AikSecretKey)
	assert.NoError(t, err)

	tpmFactory, err := NewTpmFactory()
	assert.NoError(t, err)
	assert.NotEqual(t, tpmFactory, nil)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(threadNum int) {
			defer wg.Done()

			// generate some sleep somewhere under a second
			sleep := rand.Int63n(1000)
			fmt.Printf("Thread[%d]: Sleeping for %d milliseconds\n", threadNum, sleep)
			time.Sleep(time.Duration(sleep))

			tpm, err := tpmFactory.NewTpmProvider()
			assert.NoError(t, err)

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

	simulator.Stop()
}