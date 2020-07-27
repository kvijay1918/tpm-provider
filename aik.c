/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"
#include <tss2/tss2_mu.h>

//-------------------------------------------------------------------------------------------------
// G E T   P U B   A K
// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_getpubak.c
//-------------------------------------------------------------------------------------------------
static int getpubak(TSS2_SYS_CONTEXT *sys, 
                    TPM2B_AUTH* secretKey, 
                    TPM2B_AUTH* aikSecretKey) 
{
    TSS2_RC                 rval;
    TPML_PCR_SELECTION      creation_pcr;
    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;
    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_PUBLIC            out_public = TPM2B_EMPTY_INIT;
    TPM2B_NONCE             nonce_caller = TPM2B_EMPTY_INIT;
    TPMT_TK_CREATION        creation_ticket = TPMT_TK_CREATION_EMPTY_INIT;
    TPM2B_CREATION_DATA     creation_data = TPM2B_EMPTY_INIT;
    TPM2B_ENCRYPTED_SECRET  encrypted_salt = TPM2B_EMPTY_INIT;
    TPM2B_SENSITIVE_CREATE  inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    TPM2B_PUBLIC            inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PRIVATE           out_private = TPM2B_TYPE_INIT(TPM2B_PRIVATE, buffer);
    TPM2B_DIGEST            creation_hash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMI_SH_POLICY          sessionHandle = 0; 

    TSS2L_SYS_AUTH_COMMAND sessions_data = {1, {
    {
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    creation_pcr.count = 0;

    if (secretKey == NULL) 
    {
        ERROR("The owner secret key cannot be null");
        return -1;
    }

    if (aikSecretKey == NULL) 
    {
        ERROR("The aik secret key cannot be null");
        return -1;
    }
    
    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;
    memcpy(&inSensitive.sensitive.userAuth, aikSecretKey, sizeof(TPM2B_AUTH));

    memcpy(&sessions_data.auths[0].hmac, secretKey, sizeof(TPM2B_AUTH));

    {   // from set_key_algorithm
        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;
        inPublic.publicArea.type = TPM2_ALG_RSA;                // -g arg (0x01)
        inPublic.publicArea.objectAttributes = 0;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SIGN_ENCRYPT;
        inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_DECRYPT;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
        inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
        inPublic.publicArea.authPolicy.size = 0;
        inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 0;
        inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
        inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        inPublic.publicArea.unique.rsa.size = 0;
        inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA; // -s argument (0x14)
        inPublic.publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg = TPM2_ALG_SHA256; // -D argument (0x0b)
    }

    //---------------------------------------------------------------------------------------------
    // Setup the first session 
    // TODO: this code is duplicated in activate_credential and should be moved to a util function
    TPMI_DH_OBJECT tpmKey = TPM2_RH_NULL;
    TPMI_DH_ENTITY bind = TPM2_RH_NULL;
    TPM2B_NONCE nonceNewer = TPM2B_EMPTY_INIT;
    nonceNewer.size = TPM2_SHA1_DIGEST_SIZE;                    // ???
    TPM2B_NONCE nonceCaller = TPM2B_EMPTY_INIT;
    nonceCaller.size = TPM2_SHA1_DIGEST_SIZE;                   // ???
    TPM2B_ENCRYPTED_SECRET encryptedSalt = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER salt = {0};

    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if( rval != TPM2_RC_SUCCESS )
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }
    // ---------------------------------------------------------------------------------------------

    sessions_data.auths[0].sessionHandle = sessionHandle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    rval = Tss2_Sys_Create(sys, TPM_HANDLE_EK_CERT, &sessions_data,
            &inSensitive, &inPublic, &outsideInfo, &creation_pcr, &out_private,
            &out_public, &creation_data, &creation_hash, &creation_ticket,
            &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_Create Error. TPM Error:0x%x", rval);
        return rval;
    }

    // Need to flush the session here.
    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;
    memcpy(&sessions_data.auths[0].hmac, secretKey, sizeof(TPM2B_AUTH));

    // start a second session
    rval = Tss2_Sys_StartAuthSession(sys, tpmKey, bind, 0, &nonceCaller, &encryptedSalt, TPM2_SE_POLICY, &symmetric, TPM2_ALG_SHA256, &sessionHandle, &nonceNewer, 0);
    if( rval != TPM2_RC_SUCCESS )
    {
        ERROR("Tss2_Sys_StartAuthSession Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_PolicySecret(sys, TPM2_RH_ENDORSEMENT, sessionHandle, &sessions_data, 0, 0, 0, 0, 0, 0, 0);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Tss2_Sys_PolicySecret Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = sessionHandle;
    sessions_data.auths[0].sessionAttributes |= TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    TPM2_HANDLE loaded_sha1_key_handle;
    rval = Tss2_Sys_Load(sys, TPM_HANDLE_EK_CERT, &sessions_data, &out_private, &out_public, &loaded_sha1_key_handle, &name, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_Load Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_FlushContext(sys, sessionHandle);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_Sys_FlushContext Error. TPM Error:0x%x", rval);
        return rval;
    }

    sessions_data.auths[0].sessionHandle = TPM2_RS_PW;
    sessions_data.auths[0].sessionAttributes &= ~TPMA_SESSION_CONTINUESESSION;
    sessions_data.auths[0].hmac.size = 0;

    // we use same password for endors/owner (shouldne be needed)
    memcpy(&sessions_data.auths[0].hmac, secretKey, sizeof(TPM2B_AUTH));

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, loaded_sha1_key_handle, &sessions_data, TPM_HANDLE_AIK, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    rval = Tss2_Sys_FlushContext(sys, loaded_sha1_key_handle);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("Flush transient AK error. TPM Error:0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

//-------------------------------------------------------------------------------------------------
// G E T   P U B   E K
// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_getpubek.c
//-------------------------------------------------------------------------------------------------
static int getpubek(const tpmCtx* ctx, 
                    TPM2B_AUTH* secretKey) 
{
    TSS2_RC                 rval;
    TPM2_HANDLE             handle2048ek;
    TPML_PCR_SELECTION      creationPCR;
    TPM2B_SENSITIVE_CREATE  inSensitive = TPM2B_TYPE_INIT(TPM2B_SENSITIVE_CREATE, sensitive);
    TPM2B_PUBLIC            inPublic = TPM2B_TYPE_INIT(TPM2B_PUBLIC, publicArea);
    TPM2B_DATA              outsideInfo = TPM2B_EMPTY_INIT;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_PUBLIC            outPublic = TPM2B_EMPTY_INIT;
    TPM2B_CREATION_DATA     creationData = TPM2B_EMPTY_INIT;
    TPM2B_DIGEST            creationHash = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPMT_TK_CREATION        creationTicket = TPMT_TK_CREATION_EMPTY_INIT;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
    
    TSS2L_SYS_AUTH_COMMAND sessionsData = { 1, {{
        .sessionHandle = TPM2_RS_PW,
        .nonce = TPM2B_EMPTY_INIT,
        .hmac = TPM2B_EMPTY_INIT,
        .sessionAttributes = 0,
    }}};

    if (secretKey == NULL) 
    {
        ERROR("The owner secret key cannot be null");
        return -1;
    }

    memcpy(&sessionsData.auths[0].hmac, secretKey, sizeof(TPM2B_AUTH));

    inSensitive.sensitive.data.size = 0;
    inSensitive.size = inSensitive.sensitive.userAuth.size + 2;

    {
        uint8_t* nvBytes;
        int nvLen;

        rval = NvRead(ctx, (uint8_t*)secretKey->buffer, secretKey->size, 0x1c00004, &nvBytes, &nvLen);
        if (rval != TPM2_RC_SUCCESS) 
        {
            ERROR("NvRead Error. TPM Error:0x%x", rval);
            if (nvBytes)
            {
                free(nvBytes);
            }

            return rval;
        }


        rval = Tss2_MU_TPMT_PUBLIC_Unmarshal(nvBytes, nvLen, 0, &inPublic.publicArea);
        free(nvBytes);

        rval = NvRead(ctx, (uint8_t*)secretKey->buffer, secretKey->size, 0x1c00003, &nvBytes, &nvLen);
        if (rval != TPM2_RC_SUCCESS) 
        {
            ERROR("NvRead Error. TPM Error:0x%x", rval);
            if (nvBytes)
            {
                free(nvBytes);
            }

            return rval;
        }


        memset(&inPublic.publicArea.unique, 0, sizeof(inPublic.publicArea.unique));
        memcpy(&inPublic.publicArea.unique.rsa.buffer, nvBytes, nvLen);
//        inPublic.publicArea.unique.rsa.size = 256;
        inPublic.publicArea.unique.rsa.size = 256;
        free(nvBytes);

        // DEBUG("Unique len: %x", sizeof(inPublic.publicArea.unique.rsa.buffer));
        // DEBUG("Nonce len: %x", nvLen);

        DEBUG("PA Type: %d", inPublic.publicArea.type);
        DEBUG("PA Alg:  %x", inPublic.publicArea.nameAlg);
        DEBUG("PA Attr: %x", inPublic.publicArea.objectAttributes);
        DEBUG("PA auth size: %x", inPublic.publicArea.authPolicy.size);
        DEBUG("Sym Algo: %x", inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm);
        DEBUG("Sym Keybits: %x", inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits);
        DEBUG("Sym mode: %x", inPublic.publicArea.parameters.rsaDetail.symmetric.mode);
        DEBUG("Scheme: %x", inPublic.publicArea.parameters.rsaDetail.scheme.scheme);
        DEBUG("PA Keybits: %x", inPublic.publicArea.parameters.rsaDetail.keyBits);
        DEBUG("PA exponent: %x", inPublic.publicArea.parameters.rsaDetail.exponent);






        // from set_key_algorithm

        // static BYTE auth_policy[] = {
        //         0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
        //         0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
        //         0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        // };

//        inPublic.publicArea.nameAlg = TPM2_ALG_SHA256;

        // // First clear attributes bit field.
        // inPublic.publicArea.objectAttributes = 0;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
        // inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_USERWITHAUTH;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_ADMINWITHPOLICY;
        // inPublic.publicArea.objectAttributes &= ~TPMA_OBJECT_SIGN_ENCRYPT;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
        // inPublic.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
        // inPublic.publicArea.authPolicy.size = ARRAY_SIZE(auth_policy);
        // memcpy(inPublic.publicArea.authPolicy.buffer, auth_policy, ARRAY_SIZE(auth_policy));

        // // inPublic.publicArea.type = TPM2_ALG_RSA; // 0x1 from command line
        // // inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
        // // inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
        // // inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        // // inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
        // // inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
        // // inPublic.publicArea.parameters.rsaDetail.exponent = 0;
        // // inPublic.publicArea.unique.rsa.size = 256;

        // inPublic.publicArea.type = TPM2_ALG_ECC ;
        // inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
        // inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        // inPublic.publicArea.parameters.eccDetail.symmetric.mode.sym = TPM2_ALG_CFB;
        // inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        // inPublic.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        // inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        // inPublic.publicArea.unique.ecc.x.size = 32;
        // inPublic.publicArea.unique.ecc.y.size = 32;
    }

    creationPCR.count = 0;

    /* Create EK and get a handle to the key */
    rval = Tss2_Sys_CreatePrimary(ctx->sys, TPM2_RH_ENDORSEMENT, 
            &sessionsData, &inSensitive, &inPublic, &outsideInfo, &creationPCR,
            &handle2048ek, &outPublic, &creationData, &creationHash,
            &creationTicket, &name, &sessionsDataOut);

    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("TPM2_CreatePrimary Error. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("EK create success. Got handle: 0x%8.8x", handle2048ek);

    memcpy(&sessionsData.auths[0].hmac, secretKey, sizeof(TPM2B_AUTH));

    rval = Tss2_Sys_EvictControl(ctx->sys, TPM2_RH_OWNER, handle2048ek, &sessionsData, TPM_HANDLE_EK_CERT, &sessionsDataOut);
    if (rval != TPM2_RC_SUCCESS) 
    {
        ERROR("EvictControl failed. Could not make EK persistent. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("EvictControl EK persistent success.");

    rval = Tss2_Sys_FlushContext(ctx->sys, handle2048ek);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Flush transient EK failed. TPM Error:0x%x", rval);
        return rval;
    }

    DEBUG("Flush transient EK success.");
    return rval;
}


//-------------------------------------------------------------------------------------------------
//
// This function implements the following commands (see cicd/tpm2_commands.sh)
//
// tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
// tpm2_readpublic -H 0x81010000 -o /tmp/endorsementkeyecpub
// tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beeffeedbeeffeedbeeffeedbeeffeedbeeffeed -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName -g 0x1
// 
//-------------------------------------------------------------------------------------------------
int CreateAik(const tpmCtx* ctx, 
              const uint8_t* ownerSecretKey, 
              size_t ownerSecretKeyLength, 
              const uint8_t* aikSecretKey, 
              size_t aikSecretKeyLength)
{

    TSS2_RC     rval;
    TPM2_HANDLE handle2048rsa = 0;
    TPM2B_AUTH  ownerAuth = {0};
    TPM2B_AUTH  aikAuth = {0};

    rval = InitializeTpmAuth(&ownerAuth, ownerSecretKey, ownerSecretKeyLength);
    if(rval != 0)
    {
        ERROR("There was an error creating the tpm owner secret");
        return rval;
    }

    rval = InitializeTpmAuth(&aikAuth, aikSecretKey, aikSecretKeyLength);
    if(rval != 0)
    {
        ERROR("There was an error creating the aik secret");
        return rval;
    }

    //
    // tpm2_getpubek -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -H 0x81010000 -g 0x1 -f /tmp/endorsementKey
    //
    if(PublicKeyExists(ctx, TPM_HANDLE_EK_CERT) != 0)
    {
        rval = getpubek(ctx, &ownerAuth);
        if(rval != TPM2_RC_SUCCESS)
        {
            return rval;
        }
    }
    else
    {
        DEBUG("The EK handle at %x already exists and won't be created", TPM_HANDLE_EK_CERT);
    }
    

    //
    // tpm2_getpubak -e hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -o hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -P hex:beeffeedbeeffeedbeeffeedbeeffeedbeeffeed -E 0x81010000 -k 0x81018000 -f /tmp/aik -n /tmp/aikName
    //
    if (PublicKeyExists(ctx, TPM_HANDLE_AIK) == 0)
    {
        DEBUG("The AIK handle at %x already exists. Clearing the existing handle", TPM_HANDLE_AIK);
        // Clear the existing provisioned AIK
        rval = ClearKeyHandle(ctx->sys, &ownerAuth, TPM_HANDLE_AIK);
        if (rval != TPM2_RC_SUCCESS)
        {
            return rval;
        }
        DEBUG("ClearKeyHandle: rval %x | TPM_HANDLE_AIK %x", rval, TPM_HANDLE_AIK);
    }

    // Provision the newly minted AIK
    rval = getpubak(ctx->sys, &ownerAuth, &aikAuth);
    if (rval != TPM2_RC_SUCCESS)
    {
        return rval;
    }
    DEBUG("getpubak: rval %x | TPM_HANDLE_AIK %x", rval, TPM_HANDLE_AIK);
    
    return TSS2_RC_SUCCESS;
}

int GetAikName(const tpmCtx* ctx, 
               uint8_t** aikName, 
               int* aikNameLength)
{
    TSS2_RC                 rval;
    TPM2B_PUBLIC            aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME              qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &name, &qualifiedName, &sessionsData);
    if(rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if (name.size == 0 || name.size > ARRAY_SIZE(name.name))
    {
        ERROR("Invalid aik name length: %x", name.size)
        return -1;
    }

    *aikName = calloc(name.size, 1);
    if(!*aikName)
    {
        ERROR("Could not allocate aik name buffer");
        return -1;
    }

    memcpy(*aikName, name.name, name.size);
    *aikNameLength = name.size;
    
    return 0;
}

int GetAikBytes(const tpmCtx* ctx, 
                uint8_t** const aikBytes, 
                int* const aikBytesLength)
{
    TSS2_RC                 rval;
    TPM2B_PUBLIC            aikPublic = TPM2B_EMPTY_INIT;
    TPM2B_NAME              aikName = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME              qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, TPM_HANDLE_AIK, NULL, &aikPublic, &aikName, &qualifiedName, &sessionsData);
    if(rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if(aikPublic.publicArea.unique.rsa.size == 0 || aikPublic.publicArea.unique.rsa.size > ARRAY_SIZE(aikPublic.publicArea.unique.rsa.buffer))
    {
        ERROR("Incorrect aik buffer length %x", aikPublic.publicArea.unique.rsa.size);
        return -1;   
    }

    *aikBytes = calloc(aikPublic.publicArea.unique.rsa.size, 1);
    if(!*aikBytes) 
    {
        ERROR("Could not allocate aik public buffer");
        return -1;
    }

    memcpy(*aikBytes, aikPublic.publicArea.unique.rsa.buffer, aikPublic.publicArea.unique.rsa.size);
    *aikBytesLength = aikPublic.publicArea.unique.rsa.size;
    
    return 0;
}