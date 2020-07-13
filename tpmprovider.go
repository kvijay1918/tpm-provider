/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

// #include "tpm.h"
import "C"

type CertifiedKey struct {
	Version        int
	Usage          int
	PublicKey      []byte
	PrivateKey     []byte
	KeySignature   []byte
	KeyAttestation []byte
	KeyName        []byte
}

// provides go visibility to values defined in tpm.h (shared with c code)
const (
	None = C.TPM_VERSION_UNKNOWN
	V12  = C.TPM_VERSION_10 // KWT: not supported, remove
	V20  = C.TPM_VERSION_20

	NV_IDX_ENDORSEMENT_KEY = C.NV_IDX_ENDORSEMENT_KEY
	NV_IDX_ASSET_TAG       = C.NV_IDX_ASSET_TAG
	TPM_HANDLE_AIK         = C.TPM_HANDLE_AIK
	TPM_HANDLE_EK          = C.TPM_HANDLE_EK_CERT
	TPM_HANDLE_PRIMARY     = C.TPM_HANDLE_PRIMARY

	Binding = C.TPM_CERTIFIED_KEY_USAGE_BINDING
	Signing = C.TPM_CERTIFIED_KEY_USAGE_SIGNING

	TCTI_ABRMD  = C.TCTI_ABRMD
	TCTI_DEVICE = C.TCTI_DEVICE
	TCTI_TBS    = C.TCTI_TBS
)

type TpmProvider interface {

	//
	// Releases the resources associated with the TpmProvider.
	//
	Close()

	//
	// Reports the version of the TPM (assumes TPM 2.0).
	//
	Version() C.TPM_VERSION

	//
	// Provided a 40 character hex string, takes ownership of the TPM.
	//
	TakeOwnership(ownerSecretKey string) error

	//
	// Determines if the valid, 40 character hex string currently owns
	// the TPM.
	//
	IsOwnedWithAuth(ownerSecretKey string) (bool, error)

	//
	// Used by the go-trust-agent allocate an AIK in the TPM.
	//
	CreateAik(ownerSecretKey string, aikSecretKey string) error

	//
	// Used by the go-trust-agent to facilitate handshakes with HVS
	//
	GetAikBytes() ([]byte, error)

	//
	// Used by the go-trust-agent to facilitate handshakes with HVS
	//
	GetAikName() ([]byte, error)

	//
	// ActivateCredential uses the TPM to decrypt 'secretBytes'.
	//
	// Used by the go-trust-agent to decrypt HVS data.
	//
	ActivateCredential(ownerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error)

	//
	// Used by the go-trust-agent to collect a tpm quote.
	//
	GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error)

	//
	// Checks to see if data has been written to nvram at 'nvIndex'
	//
	NvIndexExists(nvIndex uint32) (bool, error)

	//
	// Allocate nvram of size 'indexSize' at 'nvIndex'
	//
	NvDefine(ownerSecretKey string, nvIndex uint32, indexSize uint16) error

	//
	// Deletes data at nvram index 'nvIndex'
	//
	NvRelease(ownerSecretKey string, nvIndex uint32) error

	//
	// Reads data at nvram index 'nvIndex'
	//
	NvRead(tpmOwnerSecretKey string, nvIndex uint32) ([]byte, error)

	//
	// Writes data to nvram index 'nvIndex'
	//
	NvWrite(ownerSecretKey string, nvIndex uint32, data []byte) error

	//
	// Used to allocate a primary key in the TPM hiearchy that can be used by WLA to
	// create signing/binding keys.
	//
	CreatePrimaryHandle(ownerSecretKey string, handle uint32) error

	//
	// Provided valid signing/aik secret keys for the TPM, creates a CertifiedKey
	// that can be used for signing.
	//
	CreateSigningKey(signingSecretKey string, aikSecretKey string) (*CertifiedKey, error)

	//
	// Provided valid binding/aik secret keys for the TPM, creates a CertifiedKey
	// that can be used for binding.
	//
	CreateBindingKey(bindingSecretKey string, aikSecretKey string) (*CertifiedKey, error)

	//
	// ClearPublicKey clears a key from the TPM
	//
	ClearPublicKey(ownerSecretKey string, handle uint32) error

	//
	// Used by WLA to decrypt data in 'encryptedData' (using the CertifiedKey generated
	// by 'CreateBindingKey').
	//
	Unbind(certifiedKey *CertifiedKey, bindingSecretKey string, encryptedData []byte) ([]byte, error)

	//
	// Used by WLA to sign attestation reports (using the CertifiedKey generated by
	// 'CreateSigningKey').  Hash must be 32bytes long (sha256).
	//
	Sign(certifiedKey *CertifiedKey, signingSecretKey string, hash []byte) ([]byte, error)

	//
	// Checks if a primary key in the TPM exists at 'handle'.
	//
	PublicKeyExists(handle uint32) (bool, error)
}
