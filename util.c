
/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "tpm20linux.h"

#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>

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

    memcpy(auth->buffer, secretKey, secretKeyLength);
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
        ERROR("The owner auth must be provided");
        return -1;
    }

    memcpy(&sessions_data.auths[0].hmac, ownerAuth, sizeof(TPM2B_AUTH));

    TSS2L_SYS_AUTH_RESPONSE sessions_data_out;

    rval = Tss2_Sys_EvictControl(sys, TPM2_RH_OWNER, keyHandle, &sessions_data, keyHandle, &sessions_data_out);
    if (rval != TPM2_RC_SUCCESS)
    {
        ERROR("Key clearing failed. TPM2_EvictControl Error. TPM Error:0x%x", rval);
        return rval;
    }

    return rval;
}

static int tpmPublic2Rsa(TPMT_PUBLIC *public, unsigned char** rsa_buffer, int* len /*pubkey_format format, const char *path*/) {
    int ret = -1;
    RSA *ssl_rsa_key = NULL;
    BIGNUM *e = NULL, *n = NULL;

    // need this before the first SSL call for getting human readable error
    // strings in print_ssl_error()
    ERR_load_crypto_strings();

    if (public->type != TPM2_ALG_RSA) {
        ERROR("Unsupported key type for requested output format. Only RSA is supported.");
        goto error;
    }

    UINT32 exponent = (public->parameters).rsaDetail.exponent;
    if (exponent == 0) {
        exponent = 0x10001;
    }

    // OpenSSL expects this in network byte order
    ///???exponent = tpm2_util_hton_32(exponent);
    ssl_rsa_key = RSA_new();
    if (!ssl_rsa_key) {
        ERROR("Failed to allocate OpenSSL RSA structure");
        goto error;
    }

    e = BN_bin2bn((void*)&exponent, sizeof(exponent), NULL);
    n = BN_bin2bn(public->unique.rsa.buffer, public->unique.rsa.size,
                  NULL);

    if (!n || !e) {
        ERROR("Failed to convert data to SSL internal format");
        goto error;
    }

#if OPENSSL_VERSION_NUMBER < 0x1010000fL /* OpenSSL 1.1.0 */
    ssl_rsa_key->e = e;
    ssl_rsa_key->n = n;
#else
    if (!RSA_set0_key(ssl_rsa_key, n, e, NULL)) {
        ERROR("Failed to set RSA modulus and exponent components");
        goto error;
    }
#endif

    /* modulus and exponent components are now owned by the RSA struct */
    n = e = NULL;

    // fp = fopen(path, "wb");
    // if (!fp) {
    //     LOG_ERR("Failed to open public key output file '%s': %s",
    //         path, strerror(errno));
    //     goto error;
    // }

    int ssl_res = 0;

    // switch(format) {
    // case pubkey_format_pem:
    //     ssl_res = PEM_write_RSA_PUBKEY(fp, ssl_rsa_key);
    //     break;
    // case pubkey_format_der:
    //    ssl_res = i2d_RSA_PUBKEY_fp(fp, ssl_rsa_key);
        //*len = i2d_RSA_PUBKEY(ssl_rsa_key, NULL);
        *len = i2d_RSA_PUBKEY(ssl_rsa_key, rsa_buffer);// != *len) 
        DEBUG("id2_RSA_PUBKEY: %x @ %P", *len);
    //     break;
    // default:
    //     LOG_ERR("Invalid OpenSSL target format %d encountered", format);
    //     goto error;
    // }

    // if (ssl_res <= 0) {
    //     ERROR("OpenSSL public key conversion failed");
    //     goto error;
    // }

    ret = 0;

error:
    // if (fp) {
    //     fclose(fp);
    // }
    if (n) {
        BN_free(n);
    }
    if (e) {
        BN_free(e);
    }
    if (ssl_rsa_key) {
        RSA_free(ssl_rsa_key);
    }
    ERR_free_strings();

    return ret;
}


int ReadPublic(const tpmCtx* ctx, 
                TPM_HANDLE handle,
                uint8_t** const publicBytes, 
                int* const publicBytesLength)
{
    TSS2_RC                 rval;
    TPM2B_PUBLIC            public = TPM2B_EMPTY_INIT;
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TSS2L_SYS_AUTH_RESPONSE sessionsData;
    TPM2B_NAME              qualifiedName = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_ReadPublic(ctx->sys, handle, NULL, &public, &name, &qualifiedName, &sessionsData);
    if(rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    if(public.publicArea.unique.rsa.size == 0 || public.publicArea.unique.rsa.size > ARRAY_SIZE(public.publicArea.unique.rsa.buffer))
    {
        ERROR("Incorrect buffer length %x", public.publicArea.unique.rsa.size);
        return -1;   
    }

    unsigned char* rsaBytes = NULL;
    int len;
    if (tpmPublic2Rsa(&public.publicArea, &rsaBytes, &len) != 0) {
        return -1;
    }

    DEBUG("1: allocating %x", len);

    // *publicBytes = calloc(public.publicArea.unique.rsa.size, 1);
    // if(!*publicBytes) /*  */
    // {/*  */
    //     ERROR("Could not allocate public buffer");
    //     return -1;
    // }

    // memcpy(*publicBytes, public.publicArea.unique.rsa.buffer, public.publicArea.unique.rsa.size);
    // *publicBytesLength = public.publicArea.unique.rsa.size;

    *publicBytes = calloc(len, 1);
    if(!*publicBytes) 
    {
        ERROR("Could not allocate public buffer");
        return -1;
    }

    DEBUG("2: %p", rsaBytes);

    memcpy(*publicBytes, rsaBytes, len);
    DEBUG("3");

    *publicBytesLength = len;

    DEBUG("4");

    
    return 0;
}

