/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

int Sign(const tpmCtx* ctx, 
         const char* keySecret, 
         size_t keySecretLength, 
         const char* publicKeyBytes, 
         size_t publicKeyBytesLength,
         const char* privateKeyBytes, 
         size_t privateKeyBytesLength,
         const char* hashBytes, 
         size_t hashBytesLength,
         char** const signatureBytes,
         int* const signatureBytesLength)
{
    TPM2_RC                 rval;
    TPM2_HANDLE             signingKeyHandle = 0;
    TPM2B_PRIVATE           inPrivate = {0};
    TPM2B_PUBLIC            inPublic = {0};
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND  authCommand = {0};
    TPM2B_DIGEST            hash = {0};
    TPMT_SIG_SCHEME         scheme = {0};
    TPMT_SIGNATURE          signature = {0};
    size_t                  offset = 0;
    TPM2B_NAME              name  = {0};

    TPMT_TK_HASHCHECK validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
    };

    *signatureBytesLength = 0;

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_Load
    //---------------------------------------------------------------------------------------------
    offset = 0;
    rval = Tss2_MU_TPM2B_PUBLIC_Unmarshal(publicKeyBytes, publicKeyBytesLength, &offset, &inPublic);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PUBLIC_Unmarshal returned error code: 0x%x", rval);
        return rval;
    }

    offset = 0;
    rval = Tss2_MU_TPM2B_PRIVATE_Unmarshal(privateKeyBytes, privateKeyBytesLength, &offset, &inPrivate);
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_MU_TPM2B_PRIVATE_Unmarshal returned error code: 0x%x", rval);
        return rval;
    }

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;

    name.size = sizeof(name) - 2;

    rval = Tss2_Sys_Load(ctx->sys, 
                            TPM_HANDLE_PRIMARY, 
                            &sessionData, 
                            &inPrivate,
                            &inPublic,
                            &signingKeyHandle,
                            &name,
                            NULL);

    if(rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Load returned error code: 0x%x", rval);
        return rval;
    }

    //---------------------------------------------------------------------------------------------
    // Setup parameters and call Tss2_Sys_Sign
    //---------------------------------------------------------------------------------------------
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;

    hash.size = TPM2_SHA256_DIGEST_SIZE;
    memcpy_s(hash.buffer, hashBytesLength, hashBytes, hashBytesLength);

    // key password
    authCommand.count = 1;
    authCommand.auths[0].sessionHandle = TPM2_RS_PW;
    authCommand.auths[0].hmac.size = keySecretLength;
    memcpy_s(&authCommand.auths[0].hmac.buffer, keySecretLength, keySecret, keySecretLength);

    rval = Tss2_Sys_Sign(ctx->sys, 
                            signingKeyHandle, 
                            &authCommand, 
                            &hash,
                            &scheme,
                            &validation,
                            &signature,
                            NULL);
    
    if (rval != TSS2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Sign returned error code: 0x%x", rval);
        return rval;
    }

    Tss2_Sys_FlushContext(ctx->sys, signingKeyHandle);

    //---------------------------------------------------------------------------------------------
    // Allocate and copy data for the out parameters (signatureBytes).  This will be free'd by go
    //---------------------------------------------------------------------------------------------
    
    *signatureBytes = (unsigned char*)calloc(signature.signature.rsassa.sig.size, 1);
    if (!signatureBytes)
    {
        ERROR("Could not allocate signature buffer");
        return -1;
    }

    memcpy_s(*signatureBytes, signature.signature.rsassa.sig.size, signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size);
    *signatureBytesLength = signature.signature.rsassa.sig.size;
    
    return TSS2_RC_SUCCESS;
}