// +build linux

/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

//// The following CFLAGS require 'export CGO_CFLAGS_ALLOW="-f.*"' in the executable that
//// uses tpm-provider (i.e. go-trust-agent and workload-agent).
// #cgo CFLAGS: -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo LDFLAGS: -ltss2-sys -ltss2-mu -lssl -lcrypto -ltss2-tcti-device -ltss2-tcti-mssim
// #include "tpm.h"
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

type linuxTpmFactory struct {
	TpmFactory
	tctiType uint32
	conf     string
}

const (
	INVALID_OWNER_SECRET_KEY = "Invalid owner secret key"
	INVALID_AIK_SECRET_KEY   = "Invalid aik secret key"
	Tss2RcSuccess            = 0
)

func (linuxImpl linuxTpmFactory) NewTpmProvider() (TpmProvider, error) {
	var ctx *C.tpmCtx

	var conf *C.char
	conf = nil
	if linuxImpl.conf != "" {
		conf = C.CString(linuxImpl.conf)
		defer C.free(unsafe.Pointer(conf))
	}

	ctx = C.TpmCreate((C.uint)(linuxImpl.tctiType), conf)

	if ctx == nil {
		return nil, errors.New("Could not create tpm context")
	}

	tpmProvider := tpm20Linux{tpmCtx: ctx}
	return &tpmProvider, nil
}

type tpm20Linux struct {
	tpmCtx *C.tpmCtx
}

func (t *tpm20Linux) Close() {
	C.TpmDelete(t.tpmCtx)
	t.tpmCtx = nil
}

func (t *tpm20Linux) Version() C.TPM_VERSION {
	return C.Version(t.tpmCtx)
}

func (t *tpm20Linux) TakeOwnership(ownerSecretKey string) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.TakeOwnership(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)))
	if rc != 0 {
		return fmt.Errorf("TakeOwnership returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) IsOwnedWithAuth(ownerSecretKey string) (bool, error) {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return false, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	// IsOwnedWithAuth returns 0 (true) if 'owned', -1 if 'not owned', all other values are errors
	rc := C.IsOwnedWithAuth(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)))

	if rc == 0 {
		return true, nil
	} else if rc == -1 {
		return false, nil
	}

	return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
}

func (t *tpm20Linux) GetAikBytes() ([]byte, error) {
	var returnValue []byte
	var aikPublicBytes *C.uint8_t
	var aikPublicBytesLength C.int

	rc := C.GetAikBytes(t.tpmCtx,
		&aikPublicBytes,
		&aikPublicBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("GetAikBytes returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(aikPublicBytes))

	if aikPublicBytesLength <= 0 { // max size is checked in native/c code call to GetAikBytes
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(aikPublicBytes), aikPublicBytesLength)
	return returnValue, nil
}

func (t *tpm20Linux) GetAikName() ([]byte, error) {
	var returnValue []byte
	var aikName *C.uint8_t
	var aikNameLength C.int

	rc := C.GetAikName(t.tpmCtx,
		&aikName,
		&aikNameLength)
	if rc != 0 {
		return nil, fmt.Errorf("GetAikName returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(aikName))

	if aikNameLength <= 0 { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(aikName), aikNameLength)
	return returnValue, nil
}

func (t *tpm20Linux) CreateAik(ownerSecretKey string) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.CreateAik(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)))

	if rc != 0 {
		return fmt.Errorf("An error occurred in CreateAik: %w", NewTpmProviderError(int(rc)))
	}

	return nil
}

// This is the pcr selection structure that tss2 wants when performing a quote...
//
// typedef struct {																		[[Total Size 132: 4 + (8 (i.e. sizeof(TPMS_SELECTION)) * 16)]]
// 	UINT32 count; /* number of selection structures. A value of zero is allowed. */		[[number of banks]]
// 	TPMS_PCR_SELECTION pcrSelections[TPM2_NUM_PCR_BANKS]; /* list of selections */		[[see structure below]]
// } TPML_PCR_SELECTION;
//
// And substructures/defines...
//
// typedef struct {																		[[TOTAL: 8 bytes]]
// 	TPMI_ALG_HASH hash; /* the hash algorithm associated with the selection */ 			[[2 byte uint16, ex "SHA1" --> 0x4 below]]
// 	UINT8 sizeofSelect; /* the size in octets of the pcrSelect array */					[[1 byte]]
// 	BYTE pcrSelect[TPM2_PCR_SELECT_MAX]; /* the bit map of selected PCR */				[[4 byte bit mask]]
// } TPMS_PCR_SELECTION;
//
// #define TPM2_PCR_SELECT_MAX      ((TPM2_MAX_PCRS + 7) / 8) 							[[4]]
// #define TPM2_MAX_PCRS           32
// #define TPM2_NUM_PCR_BANKS      16
//
// #define TPM2_ALG_SHA1                0x0004											[["SHA1"]]
// #define TPM2_ALG_SHA256              0x000B											[["SHA256"]]
// #define TPM2_ALG_SHA384              0x000C											[["SHA384"]]
//
// Design goals were to keep the go code 'application specific' (i.e. fx that
// were needed by GTA -- no a general use TPM library).  So, we're keeping this function's
// parameters similar to the /tpm/quote endpoint (it receives a string array of pcrBanks
// and int array of pcrs).
//
// Provided it's easier to adapt those parameters to what Tss2 wants, let's do the conversion
// here.
func getPcrSelectionBytes(pcrBanks []string, pcrs []int) ([]byte, error) {

	buf := make([]byte, 132) // create a fixed size buffer for TPML_PCR_SELECTION
	offset := 0

	binary.LittleEndian.PutUint32(buf, uint32(len(pcrBanks)))
	offset += 4 // uint32

	for i, bank := range pcrBanks {
		var hash uint16
		var pcrBitMask uint32

		switch bank {
		case "SHA1":
			hash = 0x04
		case "SHA256":
			hash = 0x0B
		case "SHA384":
			hash = 0x0C
		default:
			return nil, fmt.Errorf("Invalid pcr bank type: %s", pcrBanks[i])
		}

		binary.LittleEndian.PutUint16(buf[offset:], uint16(hash))
		offset += 2 // uint16

		buf[offset] = 0x03 // 3 for 24 bits of pcrs (tss2 does not like '4')
		offset += 1        // byte

		// build a 32bit bit mask that will be applied to TPMS_PCR_SELECTION.pcrSelect
		pcrBitMask = 0
		for _, pcr := range pcrs {
			if pcr < 0 || pcr > 31 {
				return nil, fmt.Errorf("Invalid pcr value: %d", pcr)
			}

			pcrBitMask |= (1 << uint32(pcr))
		}

		binary.LittleEndian.PutUint32(buf[offset:], pcrBitMask)
		offset += 5 // uint32
	}

	return buf, nil
}

func (t *tpm20Linux) GetTpmQuote(nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error) {

	var quoteBytes []byte
	var cQuote *C.uint8_t
	var cQuoteLength C.int

	// create a buffer that describes the pcr selection that can be
	// used by tss2
	pcrSelectionBytes, err := getPcrSelectionBytes(pcrBanks, pcrs)
	if err != nil {
		return nil, err
	}

	rc := C.GetTpmQuote(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&pcrSelectionBytes[0])),
		C.size_t(len(pcrSelectionBytes)),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		C.size_t(len(nonce)),
		&cQuote,
		&cQuoteLength)

	if rc != 0 {
		return nil, fmt.Errorf("C.GetTpmQuote returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(cQuote))

	if cQuoteLength <= 0 { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The quote buffer size is incorrect")
	}

	quoteBytes = C.GoBytes(unsafe.Pointer(cQuote), cQuoteLength)
	return quoteBytes, nil
}

func (t *tpm20Linux) ActivateCredential(ownerSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error) {

	var returnValue []byte
	var decrypted *C.uint8_t
	var decryptedLength C.int

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.ActivateCredential(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)),
		(*C.uint8_t)(unsafe.Pointer(&credentialBytes[0])),
		C.size_t(len(credentialBytes)),
		(*C.uint8_t)(unsafe.Pointer(&secretBytes[0])),
		C.size_t(len(secretBytes)),
		&decrypted,
		&decryptedLength)

	if rc != 0 {
		return nil, fmt.Errorf("C.ActivateCredential returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(decrypted))

	if decryptedLength <= 0 { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(decrypted), decryptedLength)
	return returnValue, nil
}

func (t *tpm20Linux) NvDefine(ownerSecretKey string, tagSecretKey string, nvIndex uint32, nvSize uint16) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	tagSecretKeyBytes, err := validateAndConvertKey(tagSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvDefine(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)),
		(*C.uint8_t)(unsafe.Pointer(&tagSecretKeyBytes[0])),
		C.size_t(len(tagSecretKeyBytes)),
		C.uint32_t(nvIndex),
		C.uint16_t(nvSize))

	if rc != 0 {
		return fmt.Errorf("C.NVDefine returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) NvRelease(ownerSecretKey string, nvIndex uint32) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvRelease(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)),
		C.uint32_t(nvIndex))

	if rc != 0 {
		return fmt.Errorf("C.NvRelease returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) NvRead(indexSecretKey string, authHandle uint32, nvIndex uint32) ([]byte, error) {

	var returnValue []byte
	var nvData *C.uint8_t
	var nvDataLength C.int

	indexSecretKeyBytes, err := validateAndConvertKey(indexSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvRead(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&indexSecretKeyBytes[0])),
		C.size_t(len(indexSecretKeyBytes)),
		C.uint32_t(authHandle),
		C.uint32_t(nvIndex),
		&nvData,
		&nvDataLength)

	if rc != 0 {
		return nil, fmt.Errorf("C.NvRead returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(nvData))

	if nvDataLength <= 0 { // max size is checked in native/c code call to GetAikName
		return nil, fmt.Errorf("The nv data size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(nvData), nvDataLength)
	return returnValue, nil
}

func (t *tpm20Linux) NvWrite(indexSecretKey string, authHandle uint32, nvIndex uint32, data []byte) error {

	indexSecretKeyBytes, err := validateAndConvertKey(indexSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	if data == nil || len(data) == 0 {
		return errors.New("The data parameter cannot be null or empty")
	}

	rc := C.NvWrite(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&indexSecretKeyBytes[0])),
		C.size_t(len(indexSecretKeyBytes)),
		C.uint32_t(authHandle),
		C.uint32_t(nvIndex),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))

	if rc != 0 {
		return fmt.Errorf("C.NvWrite returned error code 0x%X", rc)
	}

	return nil
}

func (tpm *tpm20Linux) NvIndexExists(nvIndex uint32) (bool, error) {

	rc := C.NvIndexExists(tpm.tpmCtx, C.uint(nvIndex))
	if rc == -1 {
		return false, nil
	}

	if rc != 0 {
		return false, fmt.Errorf("NvIndexExists returned error code 0x%X", rc)
	}

	return true, nil
}

func (tpm *tpm20Linux) CreatePrimaryHandle(ownerSecretKey string, handle uint32) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.CreatePrimaryHandle(tpm.tpmCtx,
		C.uint32_t(handle),
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)))

	if rc != 0 {
		return fmt.Errorf("CreatePrimaryHandle returned error code 0x%x", rc)
	}

	return nil
}

func (tpm *tpm20Linux) CreateEk(ownerSecretKey string, handle uint32) error {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.CreateEk(tpm.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)),
		C.uint32_t(handle))

	if rc != 0 {
		return fmt.Errorf("An error occurred in CreateEk: %w", NewTpmProviderError(int(rc)))
	}

	return nil
}

func (t *tpm20Linux) CreateSigningKey(signingSecretKey string) (*CertifiedKey, error) {
	return t.createCertifiedKey(signingSecretKey, C.TPM_CERTIFIED_KEY_USAGE_SIGNING)
}

func (t *tpm20Linux) CreateBindingKey(bindingSecretKey string) (*CertifiedKey, error) {
	return t.createCertifiedKey(bindingSecretKey, C.TPM_CERTIFIED_KEY_USAGE_BINDING)
}

func (t *tpm20Linux) createCertifiedKey(keySecret string, keyUsage int) (*CertifiedKey, error) {

	keySecretBytes, err := validateAndConvertKey(keySecret)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid secret key")
	}

	var key C.CertifiedKey

	rc := C.CreateCertifiedKey(t.tpmCtx,
		&key,
		C.TPM_CERTIFIED_KEY_USAGE(keyUsage),
		(*C.uint8_t)(unsafe.Pointer(&keySecretBytes[0])),
		C.size_t(len(keySecretBytes)))

	if rc == 0 {
		defer C.free(unsafe.Pointer(key.publicKey.buffer))
		defer C.free(unsafe.Pointer(key.privateBlob.buffer))
		defer C.free(unsafe.Pointer(key.keySignature.buffer))
		defer C.free(unsafe.Pointer(key.keyAttestation.buffer))
		defer C.free(unsafe.Pointer(key.keyName.buffer))

		return &CertifiedKey{
			Version:        V20,
			Usage:          keyUsage,
			PublicKey:      C.GoBytes(unsafe.Pointer(key.publicKey.buffer), key.publicKey.size),
			PrivateKey:     C.GoBytes(unsafe.Pointer(key.privateBlob.buffer), key.privateBlob.size),
			KeySignature:   C.GoBytes(unsafe.Pointer(key.keySignature.buffer), key.keySignature.size),
			KeyAttestation: C.GoBytes(unsafe.Pointer(key.keyAttestation.buffer), key.keyAttestation.size),
			KeyName:        C.GoBytes(unsafe.Pointer(key.keyName.buffer), key.keyName.size),
		}, nil
	}

	return nil, fmt.Errorf("CreateCertifiedKey returned error code: 0x%x", rc)
}

func (t *tpm20Linux) Unbind(certifiedKey *CertifiedKey, bindingSecretKey string, encryptedData []byte) ([]byte, error) {
	var returnValue []byte
	var decryptedBytes *C.uint8_t
	var decryptedBytesLength C.int

	bindingSecretKeyBytes, err := validateAndConvertKey(bindingSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.Unbind(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&bindingSecretKeyBytes[0])),
		C.size_t(len(bindingSecretKeyBytes)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.uint8_t)(unsafe.Pointer(&encryptedData[0])),
		C.size_t(len(encryptedData)),
		&decryptedBytes,
		&decryptedBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("Unbind returned error code 0x%x", rc)
	}

	defer C.free(unsafe.Pointer(decryptedBytes))

	returnValue = C.GoBytes(unsafe.Pointer(decryptedBytes), decryptedBytesLength)
	return returnValue, nil
}

func (t *tpm20Linux) Sign(certifiedKey *CertifiedKey, signingSecretKey string, hashed []byte) ([]byte, error) {
	var returnValue []byte
	var signatureBytes *C.uint8_t
	var signatureBytesLength C.int

	signingSecretKeyBytes, err := validateAndConvertKey(signingSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	if certifiedKey == nil {
		return nil, errors.New("The certifiedKey parameter must be provided")
	}

	if len(certifiedKey.PublicKey) == 0 {
		return nil, errors.New("No data was provided in the certified key's PublicKey")
	}

	if len(certifiedKey.PrivateKey) == 0 {
		return nil, errors.New("No data was provided in the certified key's PrivateKey")
	}

	if len(hashed) == 0 {
		return nil, errors.New("No data was provided for the 'hashed' parameter")
	}

	rc := C.Sign(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&signingSecretKeyBytes[0])),
		C.size_t(len(signingSecretKeyBytes)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.uint8_t)(unsafe.Pointer(&hashed[0])),
		C.size_t(len(hashed)),
		&signatureBytes,
		&signatureBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("Sign returned error code 0x%x", rc)
	}

	defer C.free(unsafe.Pointer(signatureBytes))

	returnValue = C.GoBytes(unsafe.Pointer(signatureBytes), signatureBytesLength)
	return returnValue, nil
}

func (tpm *tpm20Linux) PublicKeyExists(handle uint32) (bool, error) {

	rc := C.PublicKeyExists(tpm.tpmCtx, C.uint(handle))
	if rc != 0 {
		return false, nil
	}

	return true, nil
}

func (t *tpm20Linux) ReadPublic(handle uint32) ([]byte, error) {
	var returnValue []byte
	var publicBytes *C.uint8_t
	var publicBytesLength C.int

	rc := C.ReadPublic(t.tpmCtx,
		C.uint(handle),
		&publicBytes,
		&publicBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("ReadPublic returned error code 0x%X", rc)
	}

	defer C.free(unsafe.Pointer(publicBytes))

	if publicBytesLength <= 0 {
		return nil, fmt.Errorf("The buffer size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(publicBytes), publicBytesLength)
	return returnValue, nil
}

func (t *tpm20Linux) IsValidEk(ownerSecretKey string, handle uint32, nvIndex uint32) (bool, error) {

	ownerSecretKeyBytes, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return false, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rval := C.IsValidEk(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&ownerSecretKeyBytes[0])),
		C.size_t(len(ownerSecretKeyBytes)),
		C.uint32_t(handle),
		C.uint32_t(nvIndex))

	if rval == 0 {
		return true, nil
	} else if rval == TPM_PROVIDER_EK_PUBLIC_MISMATCH {
		return false, nil
	} else {
		return false, NewTpmProviderError(int(rval))
	}
}

func validateAndConvertKey(key string) ([]byte, error) {

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return nil, errors.Wrap(err, "The secret key is not in a valid hex format")
	}

	// The tss library uses TP2B_AUTH structure for passwords (basically a length and
	// fixed length buffer).  The tpmprovider uses zero-copy to pass the passwords
	// into the C code.  If the password wasn't provided, return an array that contains
	// a single zero.  When passed to the C code, the TPM2B_AUTH will be an empty
	// password.
	if keyBytes == nil || len(keyBytes) == 0 {
		keyBytes = []byte{0}
	}

	return keyBytes, nil
}

// IsPcrBankActive is used to determine if a PCR bank for the specified hash algo is enabled in the TPM
func (t *tpm20Linux) IsPcrBankActive(pcrBank string) (bool, error) {
	// create a buffer that describes the pcr selection that can be used by tss2
	pcrSelectionBytes, err := getPcrSelectionBytes([]string{pcrBank}, []int{0})
	if err != nil {
		return false, errors.Wrap(err, "Unable to initialize PCR selection bytes")
	}

	// pass the buffer to the device
	rval := C.IsPcrBankActive(t.tpmCtx,
		(*C.uint8_t)(unsafe.Pointer(&pcrSelectionBytes[0])),
		C.size_t(len(pcrSelectionBytes)))

	switch rval {
	case Tss2RcSuccess:
		return true, nil
	case TPM_PROVIDER_INVALID_PCRSELECTION:
		return false, NewTpmProviderError(int(rval))
	case TPM_PROVIDER_INVALID_PCRCOUNT:
		return true, NewTpmProviderError(int(rval))
	default:
		return false, NewTpmProviderError(int(rval))
	}
}
