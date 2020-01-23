// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

// #cgo LDFLAGS: -ltss2-sys -ltss2-tcti-tabrmd -ltss2-mu -lssl -lcrypto
// #include "tpm.h"
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"unsafe"
)

type linuxTpmFactory struct {
	TpmFactory
}

const (
	TPM_SECRET_KEY_LENGTH = 40
)

func (linuxImpl linuxTpmFactory) NewTpmProvider() (TpmProvider, error) {
	var ctx *C.tpmCtx
	ctx = C.TpmCreate()

	if ctx == nil {
		return nil, errors.New("Could not create tpm context")
	}

	tpmProvider := tpm20Linux{tpmCtx: ctx}
	return &tpmProvider, nil
}

// should not be public
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

func (t *tpm20Linux) CreateSigningKey(secretKey []byte, aikSecretKey []byte) (*CertifiedKey, error) {
	return t.createCertifiedKey(secretKey, aikSecretKey, C.TPM_CERTIFIED_KEY_USAGE_SIGNING)
}

func (t *tpm20Linux) CreateBindingKey(secretKey []byte, aikSecretKey []byte) (*CertifiedKey, error) {
	return t.createCertifiedKey(secretKey, aikSecretKey, C.TPM_CERTIFIED_KEY_USAGE_BINDING)
}

func (t *tpm20Linux) createCertifiedKey(secretKey []byte, aikSecretKey []byte, keyUsage int) (*CertifiedKey, error) {

	if secretKey == nil {
		return nil, fmt.Errorf("The secret key was no provided")
	}

	if aikSecretKey == nil {
		return nil, fmt.Errorf("The aik secret key was no provided")
	}

	var key C.CertifiedKey
	defer C.free(unsafe.Pointer(key.publicKey.buffer))
	defer C.free(unsafe.Pointer(key.privateBlob.buffer))
	defer C.free(unsafe.Pointer(key.keySignature.buffer))
	defer C.free(unsafe.Pointer(key.keyAttestation.buffer))
	defer C.free(unsafe.Pointer(key.keyName.buffer))

	rc := C.CreateCertifiedKey(t.tpmCtx,
		&key,
		C.TPM_CERTIFIED_KEY_USAGE(keyUsage),
		(*C.char)(unsafe.Pointer(&secretKey[0])),
		C.size_t(len(secretKey)),
		(*C.char)(unsafe.Pointer(&aikSecretKey[0])),
		C.size_t(len(aikSecretKey)))

	if rc == 0 {
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

	return nil, fmt.Errorf("CreateCertifiedKey returned error code: %x", rc)
}

func (t *tpm20Linux) Unbind(certifiedKey *CertifiedKey, keySecret []byte, encryptedData []byte) ([]byte, error) {
	var returnValue []byte
	var decryptedBytes *C.char
	var decryptedBytesLength C.int

	rc := C.Unbind(t.tpmCtx,
		(*C.char)(unsafe.Pointer(&keySecret[0])),
		C.size_t(len(keySecret)),
		(*C.char)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.char)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.char)(unsafe.Pointer(&encryptedData[0])),
		C.size_t(len(encryptedData)),
		&decryptedBytes,
		&decryptedBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("Unbind returned error code %x", rc)
	}

	defer C.free(unsafe.Pointer(decryptedBytes))

	returnValue = C.GoBytes(unsafe.Pointer(decryptedBytes), decryptedBytesLength)
	return returnValue, nil
}

func (t *tpm20Linux) Sign(certifiedKey *CertifiedKey, keySecret []byte, hashed []byte) ([]byte, error) {
	var returnValue []byte
	var signatureBytes *C.char
	var signatureBytesLength C.int

	rc := C.Sign(t.tpmCtx,
		(*C.char)(unsafe.Pointer(&keySecret[0])),
		C.size_t(len(keySecret)),
		(*C.char)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.char)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.char)(unsafe.Pointer(&hashed[0])),
		C.size_t(len(hashed)),
		&signatureBytes,
		&signatureBytesLength)

	if rc != 0 {
		return nil, fmt.Errorf("Sign returned error code %x", rc)
	}

	defer C.free(unsafe.Pointer(signatureBytes))

	returnValue = C.GoBytes(unsafe.Pointer(signatureBytes), signatureBytesLength)
	return returnValue, nil
}

func (t *tpm20Linux) TakeOwnership(tpmOwnerSecretKey string) error {

	cTpmOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecretKey))

	rc := C.TakeOwnership(t.tpmCtx, cTpmOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)))
	if rc != 0 {
		return fmt.Errorf("TakeOwnership returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) IsOwnedWithAuth(tpmOwnerSecretKey string) (bool, error) {
	var newSecretKey = ""

	// attempt 1 - old osk = 0 | new osk - NEWKEY
	// convert go-string to C-string
	cTpmNewOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	cTpmOldOwnerSecretKey := C.CString(newSecretKey)
	defer C.free(unsafe.Pointer(cTpmOldOwnerSecretKey))
	defer C.free(unsafe.Pointer(cTpmNewOwnerSecretKey))

	// IsOwnedWithAuth returns 0 (true) if 'owned', -1 if 'not owned', all other values are errors
	rc := C.IsOwnedWithAuth(t.tpmCtx, cTpmOldOwnerSecretKey, C.size_t(len(newSecretKey)), cTpmNewOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)))

	if rc == 0 {
		// The TPM was not owned viz. it had been cleared. Ownership taken with the provided secret.
		return true, nil
	} else if rc == -1 {
		// Attempt 1 failed Failed
		// attempt 2 - old osk = NEWKEY | new osk - RANDOM_KEY
		randomSecretBytes := make([]byte, TPM_SECRET_KEY_LENGTH)
		randomSecretIntBytes, _ := rand.Read(randomSecretBytes)
		randomSecretKey := string(randomSecretIntBytes)

		cTpmOldOwnerSecretKey = C.CString(tpmOwnerSecretKey)
		cTpmNewOwnerSecretKey = C.CString(randomSecretKey)
		rc := C.IsOwnedWithAuth(t.tpmCtx, cTpmOldOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)), cTpmNewOwnerSecretKey, C.size_t(len(randomSecretKey)))
		// The TPM ownership is taken with the random secret
		if rc == 0 {
			// now we can switch the keys around to restore ownership to the user's key
			// attempt 3 - old osk = RANDOM_KEY | new osk - NEW_KEY
			//C.free(unsafe.Pointer(cTpmOldOwnerSecretKey))
			//C.free(unsafe.Pointer(cTpmNewOwnerSecretKey))
			cTpmOldOwnerSecretKey = C.CString(randomSecretKey)
			cTpmNewOwnerSecretKey = C.CString(tpmOwnerSecretKey)
			rc := C.IsOwnedWithAuth(t.tpmCtx, cTpmOldOwnerSecretKey, C.size_t(len(randomSecretKey)), cTpmNewOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)))
			if rc == 0 {
				// The TPM ownership has been set with the provided owner secret
				return true, nil
			} else if rc == -1 {
				// The TPM ownership cannot be set with the provided owner secret
				return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
			}
		} else if rc == -1 {
			return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
		}
	}
	return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
}

func (t *tpm20Linux) GetAikBytes(tpmOwnerSecretKey string) ([]byte, error) {
	var returnValue []byte
	var aikPublicBytes *C.char
	var aikPublicBytesLength C.int

	cTpmOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecretKey))

	rc := C.GetAikBytes(t.tpmCtx, cTpmOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)), &aikPublicBytes, &aikPublicBytesLength)
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

func (t *tpm20Linux) GetAikName(tpmOwnerSecretKey string) ([]byte, error) {
	var returnValue []byte
	var aikName *C.char
	var aikNameLength C.int

	cTpmOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecretKey))

	rc := C.GetAikName(t.tpmCtx, cTpmOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)), &aikName, &aikNameLength)
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

func (t *tpm20Linux) CreateAik(tpmOwnerSecretKey string, aikSecretKey string) error {

	cTpmOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecretKey))

	cAikSecretKey := C.CString(aikSecretKey)
	defer C.free(unsafe.Pointer(cAikSecretKey))

	rc := C.CreateAik(t.tpmCtx, cTpmOwnerSecretKey, C.size_t(len(tpmOwnerSecretKey)), cAikSecretKey, C.size_t(len(aikSecretKey)))
	if rc != 0 {
		return fmt.Errorf("CreateAik return 0x%x", rc)
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
//
// Yes, we could reference tss2_tpm2_types.h and build those structures directly
// in go.  But, this is the only application specific function that requires structured
// parameters -- the intent was to hide the Tss2 dependencies in tpm20linux.h (not tpm.h)
// so that we could plug in other native implementations (ex. tpm20windows.h could use
// TSS MSR c++).
//
// Is it the right approach for layering? Maybe not, but we're in the red zone and we're
// gonna stick with it.  Let's build the TPML_PCR_SELECTION structure and pass it in as
// bytes, c will cast it to the structure.
//
// KWT:  Reevaluate layering.  Could be tpm.go (interface) -> tpm20linux.go (translates go
// parameters tss2 structures) -> tss2 call. Right now it is tpm.go -> tpm20linux.go -> c code
// (translation of raw buffers to tss structures) -> tss2 call.
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

func (t *tpm20Linux) GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error) {

	var quoteBytes []byte
	var cQuote *C.char
	var cQuoteLength C.int

	cAikSecretKey := C.CString(aikSecretKey)
	defer C.free(unsafe.Pointer(cAikSecretKey))

	cNonceBytes := C.CBytes(nonce)
	defer C.free(cNonceBytes)

	// create a buffer that describes the pcr selction that can be
	// used by tss2
	pcrSelectionBytes, err := getPcrSelectionBytes(pcrBanks, pcrs)
	if err != nil {
		return nil, err
	}

	cPcrSelectionBytes := C.CBytes(pcrSelectionBytes)
	defer C.free(cPcrSelectionBytes)

	rc := C.GetTpmQuote(t.tpmCtx,
		cAikSecretKey,
		C.size_t(len(aikSecretKey)),
		cPcrSelectionBytes,
		C.size_t(len(pcrSelectionBytes)),
		cNonceBytes,
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

func (t *tpm20Linux) ActivateCredential(tpmOwnerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error) {

	var returnValue []byte
	var decrypted *C.char
	var decryptedLength C.int

	cTpmOwnerSecretKey := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecretKey))

	cAikSecretKey := C.CString(aikSecretKey)
	defer C.free(unsafe.Pointer(cAikSecretKey))

	cCredentialBytes := C.CBytes(credentialBytes)
	defer C.free(cCredentialBytes)

	cSecretBytes := C.CBytes(secretBytes)
	defer C.free(cSecretBytes)

	rc := C.ActivateCredential(t.tpmCtx,
		cTpmOwnerSecretKey,
		C.size_t(len(tpmOwnerSecretKey)),
		cAikSecretKey,
		C.size_t(len(aikSecretKey)),
		cCredentialBytes,
		C.size_t(len(credentialBytes)),
		cSecretBytes,
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

func (t *tpm20Linux) NvDefine(tpmOwnerSecretKey string, nvIndex uint32, indexSize uint16) error {

	cTpmOwnerSecret := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecret))

	rc := C.NvDefine(t.tpmCtx,
		cTpmOwnerSecret,
		C.size_t(len(tpmOwnerSecretKey)),
		C.uint32_t(nvIndex),
		C.uint16_t(indexSize))

	if rc != 0 {
		return fmt.Errorf("C.NvRead returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) NvRelease(tpmOwnerSecretKey string, nvIndex uint32) error {

	cTpmOwnerSecret := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecret))

	rc := C.NvRelease(t.tpmCtx,
		cTpmOwnerSecret,
		C.size_t(len(tpmOwnerSecretKey)),
		C.uint32_t(nvIndex))

	if rc != 0 {
		return fmt.Errorf("C.NvRelease returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20Linux) NvRead(tpmOwnerSecretKey string, nvIndex uint32) ([]byte, error) {

	var returnValue []byte
	var nvData *C.char
	var nvDataLength C.int

	cTpmOwnerSecret := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecret))

	rc := C.NvRead(t.tpmCtx,
		cTpmOwnerSecret,
		C.size_t(len(tpmOwnerSecretKey)),
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

func (t *tpm20Linux) NvWrite(tpmOwnerSecretKey string, handle uint32, data []byte) error {

	cData := C.CBytes(data)
	defer C.free(unsafe.Pointer(cData))

	cTpmOwnerSecret := C.CString(tpmOwnerSecretKey)
	defer C.free(unsafe.Pointer(cTpmOwnerSecret))

	rc := C.NvWrite(t.tpmCtx,
		cTpmOwnerSecret,
		C.size_t(len(tpmOwnerSecretKey)),
		C.uint32_t(handle),
		cData,
		C.size_t(len(data)))

	if rc != 0 {
		return fmt.Errorf("C.NvWrite returned error code 0x%X", rc)
	}

	return nil
}

func (tpm *tpm20Linux) NvIndexExists(nvIndex uint32) (bool, error) {
	rc := C.NvIndexExists(tpm.tpmCtx, C.uint(nvIndex))
	if rc == -1 {
		return false, nil // KWT:  Differentiate between and error and index not there
	}

	if rc != 0 {
		return false, fmt.Errorf("NvIndexExists returned error code 0x%X", rc)
	}

	return true, nil
}

func (tpm *tpm20Linux) CreatePrimaryHandle(tpmOwnerSecretKey []byte, handle uint32) error {

	rc := C.CreatePrimaryHandle(tpm.tpmCtx,
		C.uint32_t(handle),
		(*C.char)(unsafe.Pointer(&tpmOwnerSecretKey[0])),
		C.size_t(len(tpmOwnerSecretKey)))

	if rc != 0 {
		return fmt.Errorf("Unbind returned error code %x", rc)
	}

	return nil
}

func (tpm *tpm20Linux) PublicKeyExists(handle uint32) (bool, error) {
	rc := C.PublicKeyExists(tpm.tpmCtx, C.uint(handle))
	if rc != 0 {
		return false, nil // KWT:  Differentiate between and error and index not there
	}

	return true, nil
}

func (tpm *tpm20Linux) ReadPublic(tpmOwnerSecretKey string, handle uint32) ([]byte, error) {

	var returnValue []byte
	var public *C.char
	var publicLength C.int

	rc := C.ReadPublic(tpm.tpmCtx, C.uint(handle), &public, &publicLength)
	if rc != 0 {
		return nil, fmt.Errorf("C.ReadPublic returned %x", rc)
	}

	defer C.free(unsafe.Pointer(public))

	if publicLength <= 0 {
		return nil, fmt.Errorf("The public size is incorrect")
	}

	returnValue = C.GoBytes(unsafe.Pointer(public), publicLength)
	return returnValue, nil

}
