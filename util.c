
#include "tpm20linux.h"

//#include <stdio.h>
#include <ctype.h>

// Utility function that takes an ascii string and converts it into a TPM2B_AUTH similar
// to https://raw.githubusercontent.com/tpm2-software/tpm2-tools/3.1.0/lib/tpm2_util.c
// (tpm2_util_hex_to_byte_structure).
int str2Tpm2bAuth(const char* tpmSecretKey, size_t keyLength, TPM2B_AUTH* tpm2bAuth) 
{
    int i = 0;

    if(tpmSecretKey == NULL)
    {
        ERROR("The TPM secret key must be provided.")
        return -1;
    }

    if(keyLength == 0 || keyLength > ARRAY_SIZE(tpm2bAuth->buffer))
    {
        ERROR("Invalid secret key length.")
        return -2;
    }

//    DEBUG("SK: '%s'", tpmSecretKey);

    if (tpm2bAuth == NULL)
    {
        ERROR("TPM2B_AUTH was not provided");
        return -3;
    }

    if (keyLength % 2)
    {
        ERROR("The tpm key must be even in length");
        return -4;
    }

    if (keyLength/2 > ARRAY_SIZE(tpm2bAuth->buffer))
    {
        ERROR("Invalid key length");
        return -5;
    }

    tpm2bAuth->size = keyLength/2;

    for (i = 0; i < tpm2bAuth->size; i++) 
    {
        char tmpStr[4] = { 0 };
        tmpStr[0] = tpmSecretKey[i * 2];
        tmpStr[1] = tpmSecretKey[i * 2 + 1];
        tpm2bAuth->buffer[i] = strtol(tmpStr, NULL, 16);
    }

    return 0;
}

int InitializeTpmAuth(TPM2B_AUTH* auth, const char* secretKey, size_t secretKeyLength)
{
    if(!auth)
    {
        ERROR("Auth not provided");
        return -1;
    }

    if(!secretKey)
    {
        ERROR("Null secret key provided");
        return -1;
    }

    if(secretKeyLength == 0 || secretKeyLength > ARRAY_SIZE(auth->buffer))
    {
        ERROR("Invalid secret key length: %d", secretKeyLength);
        return -1;
    }

    memcpy_s(auth->buffer, secretKeyLength, secretKey, secretKeyLength);
    auth->size = secretKeyLength;

    return 0;
}

//
// Returns an integer value indicating the status of the public key at handle 'handle'.
// Zero:     Public key exists at 'handle'
// Negative: Public key does not exist at 'handle'
// Positive: Error code from Tss2_Sys_ReadPublic
//
int PublicKeyExists(const tpmCtx* ctx, uint32_t handle)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_PUBLIC            inPublic = TPM2B_EMPTY_INIT;;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME              qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
//    DEBUG("Tss2_Sys_ReadPublic of handle 0x%x returned 0x%0x", handle, rval);
    if(rval == 0x18b)
    {
        rval = -1;
    }
 
    return rval;
}


int ReadPublic(const tpmCtx* ctx, 
               uint32_t handle, 
               char** const public, 
               int* const publicLength)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TPM2B_PUBLIC            inPublic = TPM2B_EMPTY_INIT;;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NAME              qualified_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, 0, &inPublic, &name, &qualified_name, &sessionsDataOut);
    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if(inPublic.publicArea.unique.rsa.size == 0 || inPublic.publicArea.unique.rsa.size > ARRAY_SIZE(inPublic.publicArea.unique.rsa.buffer))
    {
        ERROR("ReadPublic:  Invalid buffer size");
        return -1;
    }

    // this will be freed by cgo in tpmlinx20.go
    *public = (char*)calloc(inPublic.publicArea.unique.rsa.size, 1);
    if (!*public)
    {
        ERROR("ReadPublic: Could not allocated buffer");
        return -1;
    }

    memcpy_s(*public, inPublic.publicArea.unique.rsa.size, inPublic.publicArea.unique.rsa.buffer, inPublic.publicArea.unique.rsa.size);
    *publicLength = inPublic.publicArea.unique.rsa.size;

    return 0;
}

//
// ClearKeyHandle clears a key from the TPM. Returns an integer value indicating whether the key was cleared:
// Zero:     Key at handle cleared
// Non-zero: Key clearing failed. Error code from Tss2_Sys_EvictControl.
//
int ClearKeyHandle(TSS2_SYS_CONTEXT *sys, TPM2B_AUTH *ownerAuth, TPM_HANDLE keyHandle)
{
    TSS2_RC rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {{
                                                   .sessionHandle = TPM2_RS_PW,
                                                   .nonce = TPM2B_EMPTY_INIT,
                                                   .hmac = TPM2B_EMPTY_INIT,
                                                   .sessionAttributes = 0,
                                               }}};

    memcpy_s(&sessions_data.auths[0].hmac, sizeof(TPM2B_AUTH), ownerAuth, sizeof(TPM2B_AUTH));

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, keyHandle, &sessions_data, keyHandle, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Key clearing failed. TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    return rval;
}