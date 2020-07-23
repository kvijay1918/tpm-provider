/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

//-------------------------------------------------------------------------------------------------
// CGO
//
// Windows...
// - Link to tss2-sys.dll, tss2-mu.dll and tss2-tcti-tbs.dll in the 'out' subdirectory.
// - Add 'include' folder to path in the git submodule at tpm2-tss directory
//
// ...
// - Link to system installed tss2 libraries and other libraries
//
// Include "tpm.h" for both.
//-------------------------------------------------------------------------------------------------

// #cgo windows LDFLAGS: -L out -ltss2-sys -ltss2-mu -ltss2-tcti-tbs
// #cgo windows CFLAGS: -Itpm2-tss/include
// #cgo linux CFLAGS: -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fstack-protector-strong
// #cgo linux LDFLAGS: -ltss2-sys -ltss2-tcti-tabrmd -ltss2-mu -lssl -lcrypto -ltss2-tcti-device
// #include "tpm.h"
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	commLog "intel/isecl/lib/common/v2/log"
	"runtime"
	"unsafe"

	"github.com/pkg/errors"
)

type tpmFactory struct {
	tctiType uint32
}

var log = commLog.GetDefaultLogger()

const (
	INVALID_OWNER_SECRET_KEY = "Invalid owner secret key"
	INVALID_AIK_SECRET_KEY   = "Invalid aik secret key"
)

func (impl tpmFactory) NewTpmProvider() (TpmProvider, error) {
	var ctx *C.tpmCtx
	ctx = C.TpmCreate((C.uint)(impl.tctiType))

	if ctx == nil {
		return nil, errors.New("Could not create tpm context")
	}

	tpmProvider := tpm20{tpmCtx: ctx}
	return &tpmProvider, nil
}

type tpm20 struct {
	tpmCtx *C.tpmCtx
}

func (t *tpm20) Close() {
	C.TpmDelete(t.tpmCtx)
	t.tpmCtx = nil
}

func (t *tpm20) Version() C.TPM_VERSION {
	return C.Version(t.tpmCtx)
}

func (t *tpm20) TakeOwnership(ownerSecretKey string) error {

	if runtime.GOOS == GOOS_WINDOWS {
		return errors.New("TakeOwnership is not applicable to Windows")
	} else if runtime.GOOS != GOOS_LINUX {
		return &UnsupportGOOSError{}
	}

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.TakeOwnership(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen)
	if rc != 0 {
		return fmt.Errorf("TakeOwnership returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20) IsOwnedWithAuth(ownerSecretKey string) (bool, error) {

	// On windows with TBS, since no auth is required, assume that is owned will
	// be true and just log a debug message.
	if runtime.GOOS == GOOS_WINDOWS {
		log.Debug("Windows does not requires owner auth")
		return true, nil
	} else if runtime.GOOS != GOOS_LINUX {
		return false, &UnsupportGOOSError{}
	}

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return false, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	// IsOwnedWithAuth returns 0 (true) if 'owned', -1 if 'not owned', all other values are errors
	rc := C.IsOwnedWithAuth(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen)

	if rc == 0 {
		return true, nil
	} else if rc == -1 {
		return false, nil
	}

	return false, fmt.Errorf("IsOwnedWithAuth returned error code 0x%X", rc)
}

func (t *tpm20) GetAikBytes() ([]byte, error) {
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

func (t *tpm20) GetAikName() ([]byte, error) {
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

func (t *tpm20) CreateAik(ownerSecretKey string, aikSecretKey string) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	aikSecretKeyBytes, aikSecretKeyBytesLen, err := validateAndConvertKey(aikSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_AIK_SECRET_KEY)
	}

	rc := C.CreateAik(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
		aikSecretKeyBytes,
		aikSecretKeyBytesLen)

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
// parameters -- the intent was to hide the Tss2 dependencies in tpm20.h (not tpm.h)
// so that we could plug in other native implementations (ex. tpm20windows.h could use
// TSS MSR c++).
//
// Is it the right approach for layering? Maybe not, but we're in the red zone and we're
// gonna stick with it.  Let's build the TPML_PCR_SELECTION structure and pass it in as
// bytes, c will cast it to the structure.
//
// KWT:  Reevaluate layering.  Could be tpm.go (interface) -> tpm20.go (translates go
// parameters tss2 structures) -> tss2 call. Right now it is tpm.go -> tpm20.go -> c code
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

func (t *tpm20) GetTpmQuote(aikSecretKey string, nonce []byte, pcrBanks []string, pcrs []int) ([]byte, error) {

	var quoteBytes []byte
	var cQuote *C.uint8_t
	var cQuoteLength C.int

	aikSecretKeyBytes, aikSecretKeyBytesLen, err := validateAndConvertKey(aikSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_AIK_SECRET_KEY)
	}

	// create a buffer that describes the pcr selction that can be
	// used by tss2
	pcrSelectionBytes, err := getPcrSelectionBytes(pcrBanks, pcrs)
	if err != nil {
		return nil, err
	}

	rc := C.GetTpmQuote(t.tpmCtx,
		aikSecretKeyBytes,
		aikSecretKeyBytesLen,
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

func (t *tpm20) ActivateCredential(ownerSecretKey string, aikSecretKey string, credentialBytes []byte, secretBytes []byte) ([]byte, error) {

	var returnValue []byte
	var decrypted *C.uint8_t
	var decryptedLength C.int

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	aikSecretKeyBytes, aikSecretKeyBytesLen, err := validateAndConvertKey(aikSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_AIK_SECRET_KEY)
	}

	rc := C.ActivateCredential(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
		aikSecretKeyBytes,
		aikSecretKeyBytesLen,
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

func (t *tpm20) NvDefine(ownerSecretKey string, nvIndex uint32, indexSize uint16) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvDefine(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
		C.uint32_t(nvIndex),
		C.uint16_t(indexSize))

	if rc != 0 {
		return fmt.Errorf("C.NvRead returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20) NvRelease(ownerSecretKey string, nvIndex uint32) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvRelease(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
		C.uint32_t(nvIndex))

	if rc != 0 {
		return fmt.Errorf("C.NvRelease returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20) NvRead(ownerSecretKey string, nvIndex uint32) ([]byte, error) {

	var returnValue []byte
	var nvData *C.uint8_t
	var nvDataLength C.int

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.NvRead(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
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

func (t *tpm20) NvWrite(ownerSecretKey string, handle uint32, data []byte) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	if data == nil || len(data) == 0 {
		return errors.New("The data parameter cannot be null or empty")
	}

	rc := C.NvWrite(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen,
		C.uint32_t(handle),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.size_t(len(data)))

	if rc != 0 {
		return fmt.Errorf("C.NvWrite returned error code 0x%X", rc)
	}

	return nil
}

func (tpm *tpm20) NvIndexExists(nvIndex uint32) (bool, error) {

	rc := C.NvIndexExists(tpm.tpmCtx, C.uint(nvIndex))
	if rc == -1 {
		return false, nil // KWT:  Differentiate between and error and index not there
	}

	if rc != 0 {
		return false, fmt.Errorf("NvIndexExists returned error code 0x%X", rc)
	}

	return true, nil
}

func (tpm *tpm20) CreatePrimaryHandle(ownerSecretKey string, handle uint32) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.CreatePrimaryHandle(tpm.tpmCtx,
		C.uint32_t(handle),
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen)

	if rc != 0 {
		return fmt.Errorf("CreatePrimaryHandle returned error code %x", rc)
	}

	return nil
}

func (t *tpm20) CreateSigningKey(signingSecretKey string, aikSecretKey string) (*CertifiedKey, error) {
	return t.createCertifiedKey(signingSecretKey, aikSecretKey, C.TPM_CERTIFIED_KEY_USAGE_SIGNING)
}

func (t *tpm20) CreateBindingKey(bindingSecretKey string, aikSecretKey string) (*CertifiedKey, error) {
	return t.createCertifiedKey(bindingSecretKey, aikSecretKey, C.TPM_CERTIFIED_KEY_USAGE_BINDING)
}

func (t *tpm20) createCertifiedKey(keySecret string, aikSecretKey string, keyUsage int) (*CertifiedKey, error) {

	keySecretBytes, keySecretBytesLen, err := validateAndConvertKey(keySecret)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid secret key")
	}

	aikSecretKeyBytes, aikSecretKeyBytesLen, err := validateAndConvertKey(aikSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_AIK_SECRET_KEY)
	}

	var key C.CertifiedKey

	rc := C.CreateCertifiedKey(t.tpmCtx,
		&key,
		C.TPM_CERTIFIED_KEY_USAGE(keyUsage),
		keySecretBytes,
		keySecretBytesLen,
		aikSecretKeyBytes,
		aikSecretKeyBytesLen)

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

	return nil, fmt.Errorf("CreateCertifiedKey returned error code: %x", rc)
}

func (t *tpm20) ClearPublicKey(ownerSecretKey string, handle uint32) error {

	ownerSecretKeyBytes, ownerSecretKeyBytesLen, err := validateAndConvertKey(ownerSecretKey)
	if err != nil {
		return errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.ClearPublicKey(t.tpmCtx,
		ownerSecretKeyBytes,
		ownerSecretKeyBytesLen, C.uint32_t(handle))

	if rc != 0 {
		return fmt.Errorf("C.ClearPublicKey returned error code 0x%X", rc)
	}

	return nil
}

func (t *tpm20) Unbind(certifiedKey *CertifiedKey, bindingSecretKey string, encryptedData []byte) ([]byte, error) {
	var returnValue []byte
	var decryptedBytes *C.uint8_t
	var decryptedBytesLength C.int

	bindingSecretKeyBytes, bindingSecretKeyBytesLen, err := validateAndConvertKey(bindingSecretKey)
	if err != nil {
		return nil, errors.Wrap(err, INVALID_OWNER_SECRET_KEY)
	}

	rc := C.Unbind(t.tpmCtx,
		bindingSecretKeyBytes,
		bindingSecretKeyBytesLen,
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.uint8_t)(unsafe.Pointer(&encryptedData[0])),
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

func (t *tpm20) Sign(certifiedKey *CertifiedKey, signingSecretKey string, hashed []byte) ([]byte, error) {
	var returnValue []byte
	var signatureBytes *C.uint8_t
	var signatureBytesLength C.int

	signingSecretKeyBytes, signingSecretKeyBytesLen, err := validateAndConvertKey(signingSecretKey)
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
		signingSecretKeyBytes,
		signingSecretKeyBytesLen,
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PublicKey[0])),
		C.size_t(len(certifiedKey.PublicKey)),
		(*C.uint8_t)(unsafe.Pointer(&certifiedKey.PrivateKey[0])),
		C.size_t(len(certifiedKey.PrivateKey)),
		(*C.uint8_t)(unsafe.Pointer(&hashed[0])),
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

func (tpm *tpm20) PublicKeyExists(handle uint32) (bool, error) {

	rc := C.PublicKeyExists(tpm.tpmCtx, C.uint(handle))
	if rc != 0 {
		return false, nil
	}

	return true, nil
}

// Returns the pointer to the 'key' and it's length (or error).
func validateAndConvertKey(key string) (*C.uint8_t, C.size_t, error) {
	var results *C.uint8_t

	length := C.size_t(0)

	// On Windows, just return an null pointer and length '0'.  Otherwise,
	// on Linux, convert the hex string from the config.yaml to bytes and
	// return its pointer/length.
	if runtime.GOOS == GOOS_WINDOWS {
		results = (*C.uint8_t)(nil)
	} else if runtime.GOOS == GOOS_LINUX {

		if key == "" {
			return nil, length, errors.New("The secret key cannot be empty")
		}

		if len(key) != 40 {
			return nil, length, errors.New("The secret key length is invalid")
		}

		keyBytes, err := hex.DecodeString(key)
		if err != nil {
			return nil, length, errors.Wrap(err, "The secret key is not in a valid hex format")
		}

		if keyBytes == nil || len(keyBytes) == 0 {
			return nil, length, errors.Errorf("Decoding the secret key '%s' did not return any data", key)
		}

		results = (*C.uint8_t)(unsafe.Pointer(&keyBytes[0]))
		length = C.size_t(len(keyBytes))
	} else {
		return nil, 0, &UnsupportGOOSError{}
	}

	return results, length, nil
}
