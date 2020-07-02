/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20.h"

#define NV_DEFAULT_BUFFER_SIZE 512

// From https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_nv_util.h::tpm2_util_nv_max_buffer_size
static int GetMaxNvBufferSize(TSS2_SYS_CONTEXT* sys, uint32_t* size) 
{
    TSS2_RC                 rval;
    TPMS_CAPABILITY_DATA    cap_data;
    TPMI_YES_NO             more_data;

    if(!sys)
    {
        LOG_ERROR("TSS2_SYS_CONTEXT was not provided.");
    }

    if(!size)
    {
        LOG_ERROR("'size' was not provided.")
    }

    *size = 0;

    rval = Tss2_Sys_GetCapability (sys, NULL, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_NV_BUFFER_MAX, 1, &more_data, &cap_data, NULL);
    
    if (rval != TSS2_RC_SUCCESS) 
    {
        LOG_ERROR("Failed to query max transmission size via Tss2_Sys_GetCapability. Error:0x%x", rval);
    } 
    else
    {
        *size = cap_data.data.tpmProperties.tpmProperty[0].value;
    }

    if (*size > TPM2_MAX_NV_BUFFER_SIZE) 
    {
        *size = TPM2_MAX_NV_BUFFER_SIZE;
    }
    else if (*size == 0) 
    {
        *size = NV_DEFAULT_BUFFER_SIZE;
    }

    //DEBUG("Max nv buffer size is 0x%x", *size);

    return rval;
}

int NvDefine(const tpmCtx* ctx, 
             const uint8_t* ownerSecretKey, 
             size_t ownerSecretKeyLength, 
             uint32_t nvIndex, 
             uint16_t nvSize)
{
    TSS2_RC                 rval;
    TPM2B_NV_PUBLIC         publicInfo = TPM2B_EMPTY_INIT;
    TPM2B_AUTH              nvOwnerAuth = {0};
    TSS2L_SYS_AUTH_RESPONSE sessionDataOut;
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};
 
    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0) 
    {
        return rval;
    }

    rval = InitializeTpmAuth(&nvOwnerAuth, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0) 
    {
        return rval;
    }

    publicInfo.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH) + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.nvPublic.dataSize = nvSize;
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA256;
    publicInfo.nvPublic.attributes = TPMA_NV_OWNERWRITE | TPMA_NV_POLICYWRITE | TPMA_NV_OWNERREAD;
    
    rval = Tss2_Sys_NV_DefineSpace(ctx->sys, TPM2_RH_OWNER, &sessionData, &nvOwnerAuth, &publicInfo, &sessionDataOut);
    if (rval != TPM2_RC_SUCCESS) 
    {
        LOG_ERROR("Tss2_Sys_NV_DefineSpace returned error: 0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

int NvRelease(const tpmCtx* ctx, 
              const uint8_t* ownerSecretKey, 
              size_t ownerSecretKeyLength, 
              uint32_t nvIndex)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0) 
    {
        return rval;
    }
    
    rval = Tss2_Sys_NV_UndefineSpace(ctx->sys, TPM2_RH_OWNER, nvIndex, &sessionData, 0);
    if (rval != TPM2_RC_SUCCESS) 
    {
        LOG_ERROR("Tss2_Sys_NV_UndefineSpace returned error: 0x%x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

//
// Returns 0 if true, -1 for false, all other values are error codes
//
int NvIndexExists(const tpmCtx* ctx, uint32_t nvIndex)
{
    TSS2_RC         rval;
    TPM2B_NV_PUBLIC nv_public = TPM2B_EMPTY_INIT;
    TPM2B_NAME      nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nv_public, &nv_name, NULL);
    if(rval == 0x18B)
    {
        return -1;
    }
    
    return rval;
}


int NvRead(const tpmCtx* ctx, 
           const uint8_t* ownerSecretKey, 
           size_t ownerSecretKeyLength, 
           uint32_t nvIndex, 
           uint8_t** const nvBytes, 
           int* const nvBytesLength)
{
    TSS2_RC                 rval;
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};
    TPM2B_NAME              name = TPM2B_TYPE_INIT(TPM2B_NAME, name);
    TPM2B_NV_PUBLIC         nvPublic = TPM2B_EMPTY_INIT;
    TPM2B_MAX_NV_BUFFER     nvData = TPM2B_TYPE_INIT(TPM2B_MAX_NV_BUFFER, buffer);
    uint16_t                nvBufferSize = 0;               // total size of nv buffer
    uint32_t                maxNvBufferSize = 0;            // max nv size that can be read (tpm caps)
    uint16_t                off = 0;                        // offset to read from in nv buffer
    uint16_t                len = 0;                        // size of nv buffer to read

    *nvBytesLength = 0;     // return zero in case of error conditions below

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0) 
    {
        return rval;
    }

    rval = GetMaxNvBufferSize(ctx->sys, &maxNvBufferSize);
    if (rval != TSS2_RC_SUCCESS) 
    {
        LOG_ERROR("GetMaxNvBufferSize returned error: 0x%x", rval);
        return rval;
    }

    // use the Tss2_Sys_NV_ReadPublic to find the total size of the index
    rval = Tss2_Sys_NV_ReadPublic(ctx->sys, nvIndex, NULL, &nvPublic, &name, NULL);
    if (rval != TSS2_RC_SUCCESS) 
    {
        LOG_ERROR("Tss2_Sys_NV_ReadPublic returned: 0x%x", rval);
        return rval;
    }

    nvBufferSize = nvPublic.nvPublic.dataSize;
    if(nvBufferSize == 0 || nvBufferSize > TPM2_MAX_NV_BUFFER_SIZE)
    {
        LOG_ERROR("Invalid nv buffer size 0x%x", nvBufferSize);
        return -1;
    }

    *nvBytes = (uint8_t*)calloc(nvBufferSize, 1);
    if(!*nvBytes)
    {
        LOG_ERROR("Could not allocate nv buffer");
        return -1;
    }

    while(off < nvBufferSize)
    {
        len = nvBufferSize >  maxNvBufferSize ? maxNvBufferSize : nvBufferSize;
        if(off + len > nvBufferSize)
        {
            len = nvBufferSize - off;
        }

        rval = Tss2_Sys_NV_Read(ctx->sys, TPM2_RH_OWNER, nvIndex, &sessionData, len, off, &nvData, &sessionsDataOut);
        if (rval != TSS2_RC_SUCCESS) 
        {
            LOG_ERROR("Tss2_Sys_NV_Read returned: 0x%x", rval);
            free(*nvBytes);
            return rval;
        }

        if (len != nvData.size)
        {
            LOG_ERROR("The nvdata size did not match the requested length [len:0x%x, size:0x%x]", len, nvData.size);
            free(*nvBytes);
            return rval;
        }

        memcpy(*nvBytes + off, nvData.buffer, len);
        off += len;
    }

    *nvBytesLength = off;

    return TSS2_RC_SUCCESS;
}


int NvWrite(const tpmCtx* ctx, 
            const uint8_t* ownerSecretKey, 
            size_t ownerSecretKeyLength, 
            uint32_t nvIndex, 
            const uint8_t* nvBytes, 
            size_t nvBytesLength)
{
    TSS2_RC                 rval;
    size_t                  pos  = 0;        // offset into nbBytes
    uint32_t                maxNvBufferSize;
    TSS2L_SYS_AUTH_RESPONSE sessionDataOut;
    TSS2L_SYS_AUTH_COMMAND  sessionData = {0};
    TPM2B_MAX_NV_BUFFER     nvWriteData;

    sessionData.count = 1;
    sessionData.auths[0].sessionHandle = TPM2_RS_PW;
    rval = InitializeTpmAuth(&sessionData.auths[0].hmac, ownerSecretKey, ownerSecretKeyLength);
    if (rval != 0) 
    {
        return rval;
    }

    if(nvBytesLength == 0 || nvBytesLength > TPM2_MAX_NV_BUFFER_SIZE)
    {
        LOG_ERROR("Invalid nv write buffer size: 0x%x", nvBytesLength);
        return -1;
    }

    rval = GetMaxNvBufferSize(ctx->sys, &maxNvBufferSize);
    if (rval != TSS2_RC_SUCCESS) 
    {
        LOG_ERROR("GetMaxNVBufferSize returned: 0x%x", rval);
        return rval;
    }

    while (pos < nvBytesLength) 
    {
        memset(&nvWriteData, 0, sizeof(TPM2B_MAX_NV_BUFFER));
        nvWriteData.size = (nvBytesLength - pos) > maxNvBufferSize ? maxNvBufferSize : (nvBytesLength - pos);

        memcpy(nvWriteData.buffer, (nvBytes + pos), nvWriteData.size);

        rval = Tss2_Sys_NV_Write(ctx->sys, TPM2_RH_OWNER, nvIndex, &sessionData, &nvWriteData, (uint16_t)pos, &sessionDataOut);
        if (rval != TSS2_RC_SUCCESS) 
        {
            LOG_ERROR("Tss2_Sys_NV_Write returned error:0x%x", rval);
            return rval;
        }

        pos += nvWriteData.size;
    }

    return TSS2_RC_SUCCESS;
}