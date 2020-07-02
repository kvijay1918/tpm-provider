
/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tpm20.h"

#include <ctype.h>

int InitializeTpmAuth(TPM2B_AUTH* auth, const char* secretKey, size_t secretKeyLength)
{
    if(!auth)
    {
        LOG_ERROR("Auth not provided");
        return -1;
    }


#if defined(WIN32)
    // On windows, do not provide auth (TODO: this may not work for aik auth)
    memset(auth->buffer, 0, sizeof(auth->buffer));
#else
    // On linux, copy the secret key into the TPM2B_AUTH structure
    if(!secretKey)
    {
        LOG_ERROR("Null secret key provided");
        return -1;
    }

    if(secretKeyLength == 0 || secretKeyLength > ARRAY_SIZE(auth->buffer))
    {
        LOG_ERROR("Invalid secret key length: %d", secretKeyLength);
        return -1;
    }

    memcpy(auth->buffer, secretKey, secretKeyLength);
    auth->size = secretKeyLength;
#endif

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

    if (ownerAuth == NULL)
    {
        LOG_ERROR("The owner auth must be provided");
        return -1;
    }

    memcpy(&sessions_data.auths[0].hmac, ownerAuth, sizeof(TPM2B_AUTH));

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, keyHandle, &sessions_data, keyHandle, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        LOG_ERROR("Key clearing failed. TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    return rval;
}