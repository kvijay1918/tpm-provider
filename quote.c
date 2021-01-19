/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "tpm20linux.h"

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static int unset_pcr_sections(TPML_PCR_SELECTION *s) 
{
    UINT32 i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return FALSE;
            }
        }
    }

    return TRUE;
}

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static void update_pcr_selections(TPML_PCR_SELECTION *s1, TPML_PCR_SELECTION *s2) 
{
    UINT32 i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++) {
        for (i1 = 0; i1 < s1->count; i1++) {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                        ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

// from: https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_pcrlist.c
static int getPcrs(TSS2_SYS_CONTEXT* sys, 
                   TPML_PCR_SELECTION* requestedPcrs, 
                   TPML_DIGEST pcrResults[24], 
                   size_t* pcrCount)
{
    TSS2_RC             rval;
    TPML_PCR_SELECTION  pcr_selection_tmp = {0};
    TPML_PCR_SELECTION  pcr_selection_out = {0};
    UINT32              pcr_update_counter = 0;
    size_t              count = 0;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, requestedPcrs, sizeof(pcr_selection_tmp));

    do 
    {
        rval = Tss2_Sys_PCR_Read(sys, NULL, &pcr_selection_tmp,
                &pcr_update_counter, &pcr_selection_out,
                &pcrResults[count], 0);

        if (rval != TPM2_RC_SUCCESS) 
        {
            ERROR("Tss2_Sys_PCR_Read error: 0x%0x", rval);
            return rval;
        }

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        update_pcr_selections(&pcr_selection_tmp, &pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++count < 24 && !unset_pcr_sections(&pcr_selection_tmp));

    *pcrCount = count;
    return TPM2_RC_SUCCESS;
}


// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/tools/tpm2_quote.c
static int getQuote(TSS2_SYS_CONTEXT* sys, 
                    TPM2B_AUTH* akPassword,
                    TPM2_HANDLE akHandle, 
                    TPML_PCR_SELECTION *pcrSelection, 
                    TPM2B_DATA* qualifyingData, 
                    TPM2B_ATTEST* quote, 
                    TPMT_SIGNATURE* signature)
{
    TSS2_RC                 rval;
    TPMT_SIG_SCHEME         inScheme = {0};
    TSS2L_SYS_AUTH_COMMAND  sessionsData = { 1, {{.sessionHandle=TPM2_RS_PW}}};
    TSS2L_SYS_AUTH_RESPONSE sessionsDataOut = {0};

    inScheme.scheme = TPM2_ALG_NULL;

    // neded for tpm2-tss-2.0.0-4.el8.x86_64 (rhel8)
    // not needed tpm2-tss-2.1.2-1.fc29.x86_64 (fedora 29)
    memcpy(&sessionsData.auths[0].hmac, akPassword, sizeof(TPM2B_AUTH));

    memset( (void *)signature, 0, sizeof(TPMT_SIGNATURE) );

    rval = TSS2_RETRY_EXP(Tss2_Sys_Quote(sys, akHandle, &sessionsData,
            qualifyingData, &inScheme, pcrSelection, quote,
            signature, &sessionsDataOut));

    if(rval != TPM2_RC_SUCCESS)
    {
        ERROR("Tss2_Sys_Quote failed: 0x%0x", rval);
        return rval;
    }

    return TSS2_RC_SUCCESS;
}

#define DEFAULT_PCR_MEASURMENT_COUNT 24


// HVS wants a custom blob of data (format documented below based on) 
// - TpmV20.java::getQuote() (where the bytes are created)
// - 'QuoteResponse': https://github.com/microsoft/TSS.MSR/blob/master/TSS.Java/src/tss/tpm/QuoteResponse.java
// - AikQuoteVerifier2.verifyAIKQuote() (where the bytes are consumed)
//
// 
// TpmV20.java::getQuote(): Creates TpmQuote.quoteData bytes 'combined' from...
//  - QuoteResponse.toTpm()
//     - Quote...
//       - 2 bytes int of length of quote size
//       - bytes from TPMS_ATTEST (this structure contains the selected pcrs in TPMU_ATTEST)
//       ==> THIS SHOULD BE A TPM2B_ATTEST structure
//     - Signature...
//       - 2 bytes for signature algorithm
//       - TPMU_SIGNATURE structure
//       ==> THIS SHOULD BE A TPMT_SIGNATURE structure
//  - pcrResults (concatentated buffers from TPM2B_DIGEST (TpmV20.java::getPcrs())).  Going to 
//    assume full size of buffers (not using size)
// 
// (all bytes are base64 encoded in go)
static int CreateQuoteBuffer(TPM2B_ATTEST* quote, 
                             TPMT_SIGNATURE* signature, 
                             TPML_PCR_SELECTION* pcrSelection, 
                             TPML_DIGEST* pcrMeasurements,
                             uint8_t** quoteBytes, 
                             int* quoteBytesLength) 
{
    size_t      off = 0;            // offset in 'quoteBytes' to help with writing quote
    size_t      bufferSize = 0;     // total size of buffer to allocate
    uint16_t    tmp = 0;            // tmp var for bswap


    //bufferSize = sizeof(TPM2B_ATTEST) + sizeof(uint16_t) + sizeof(TPMT_SIGNATURE);
    bufferSize = sizeof(uint16_t) + quote->size + sizeof(uint16_t) + signature->signature.rsassa.sig.size;

    *quoteBytes = (uint8_t*)calloc(bufferSize, 1);
    if(!*quoteBytes) 
    {
        ERROR("Could not allocate quote buffer");
        return -1;
    }


    DEBUG("Quote Size: %x", quote->size);
    memcpy((*quoteBytes + off), &quote->size, sizeof(uint16_t));
    off += sizeof(uint16_t);

    memcpy((*quoteBytes + off), quote->attestationData, quote->size);
    off += quote->size;//sizeof(TPM2B_ATTEST);

    // DEBUG("TPMS_ATTEST @:%x", offsetof(TPM2B_ATTEST, attestationData));
    // DEBUG("magic @:%x", offsetof(TPMS_ATTEST, magic));
    // DEBUG("type @:%x", offsetof(TPMS_ATTEST, type));
    // DEBUG("qualifiedSigner @:%x", offsetof(TPMS_ATTEST, qualifiedSigner));
    // DEBUG("extraData @:%x", offsetof(TPMS_ATTEST, extraData));


    // TPMS_ATTEST* attest = (TPMS_ATTEST*)quote->attestationData;
    // DEBUG("%08x: attest->clockInfo.clock (time in milliseconds during which the TPM has been powered)", attest->clockInfo.clock);
    // DEBUG("%08x: attest->clockInfo.resetCount (number of occurrences of TPM Reset since the last TPM2_Clear)", attest->clockInfo.resetCount);
    // DEBUG("%08x: attest->clockInfo.restartCount (number of times that TPM2_Shutdown or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear.", attest->clockInfo.restartCount);


    DEBUG("SIGNATURE LEN %x AT %x", signature->signature.rsassa.sig.size, off);
    memcpy((*quoteBytes + off), &signature->signature.rsassa.sig.size, sizeof(uint16_t));
    off += sizeof(uint16_t);

    DEBUG("SIGNATURE IS AT %x", off);
//    DEBUG("SIGNATURE LENGTH %x", tmp);
//    DEBUG("SIGNATURE TYPE %x", signature->sigAlg);


    memcpy((*quoteBytes + off), signature->signature.rsassa.sig.buffer, signature->signature.rsassa.sig.size);

    *quoteBytesLength = bufferSize;
    return TSS2_RC_SUCCESS;

/*
    size_t      off = 0;            // offset in 'quoteBytes' to help with writing quote
    uint16_t    tmp = 0;            // tmp var for bswap
    size_t      bufferSize = 0;     // total size of buffer to allocate
    size_t      pcrSize = 0;        // for calculating buffer sizes of pcr measurments
    uint32_t    pcrSelectBitMask;   // tmp variable for pcr selection
    
    //
    // First determine the size of the buffer (see notes above)
    //
    bufferSize = sizeof(uint16_t) + quote->size + (sizeof(uint16_t)*3) + signature->signature.rsassa.sig.size;

    // Use pcrSelection to determine the number of bytes needed to store the pcr measurements.
    // KWT:  Use the data in the quote for pcr selection and drop 'pcrSelection' parameter...
    for (int i = 0; i < pcrSelection->count; i++)
    {
        switch(pcrSelection->pcrSelections[i].hash)
        {
        case TPM2_ALG_SHA1:
            pcrSize = 20;
            break;
        case TPM2_ALG_SHA256:
            pcrSize = 32;
            break;
        case TPM2_ALG_SHA384:
            pcrSize = 48;
            break;
        case TPM2_ALG_SHA512:
            pcrSize = 64;
            break;
        default:
            ERROR("Unknown pcr selection hash: 0x%x", pcrSelection->pcrSelections[i].hash);
            return -1;
        }        

        // pcr selection is a 4 byte bit map 
        pcrSelectBitMask = 0;
        memcpy(&pcrSelectBitMask, pcrSelection->pcrSelections[i].pcrSelect, pcrSelection->pcrSelections[i].sizeofSelect);

        for(int j = 0; j < 32; j++)
        {
            int mask = 1 << j;
            if ((pcrSelectBitMask & mask) == mask)
            {
                DEBUG("SELECTED PCR: %d, %d, 0x%x", j, pcrSize, bufferSize);
                bufferSize += pcrSize;
            }
        }
    }

    *quoteBytes = (uint8_t*)calloc(bufferSize, 1);
    if(!*quoteBytes) 
    {
        ERROR("Could not allocate quote buffer");
        return -1;
    }

    // write to the buffer
    // HVS chokes on using types tss types like 'TPM2B_ATTEST' for this due to endianess.  We 
    // have to hand marshal certain bits (using bswap16)...
    //
    // first the quote information
    tmp = __builtin_bswap16(quote->size);
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

    memcpy((*quoteBytes + off), &quote->attestationData, quote->size);
    off += quote->size;

    //
    // now the signature
    //
    tmp = __builtin_bswap16(signature->sigAlg);  
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

    tmp = __builtin_bswap16(signature->signature.rsassa.hash);  
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

    tmp = __builtin_bswap16(signature->signature.rsassa.sig.size);
    memcpy((*quoteBytes + off), &tmp, sizeof(uint16_t));
    off += sizeof(uint16_t);

    memcpy((*quoteBytes + off), &signature->signature.rsassa.sig.buffer, signature->signature.rsassa.sig.size);
    off += signature->signature.rsassa.sig.size;

    //
    // copy pcr measurements to output buffer.  Just concatenate the measurements, HVS will
    // use the pcr selections in the quote to determine theyr lengths.
    //
    for(int i = 0; i < DEFAULT_PCR_MEASURMENT_COUNT; i++)
    {
        for (int j = 0; j < pcrMeasurements[i].count; j++)
        {
            if (pcrMeasurements[i].digests[j].size == 0)
            {
                continue;
            }
            else if(pcrMeasurements[i].digests[j].size > 0 && pcrMeasurements[i].digests[j].size <= 64)
            {
                DEBUG("Copying measurement %d, digest %d, length %d at %x", i, j, pcrMeasurements[i].digests[j].size, off);
                memcpy((*quoteBytes + off), pcrMeasurements[i].digests[j].buffer, pcrMeasurements[i].digests[j].size);
                off += pcrMeasurements[i].digests[j].size;
            }
            else
            {
                ERROR("Invalid pcr measurement size 0x%x at measurement %d, digest %d", pcrMeasurements[i].digests[j].size, i, j);
                return -1;
            }
        }
    }

    *quoteBytesLength = bufferSize;
    return TSS2_RC_SUCCESS;
*/
}

int GetTpmQuote(const tpmCtx* ctx, 
                const uint8_t* aikSecretKey, 
                size_t aikSecretKeyLength, 
                const uint8_t* pcrSelectionBytes,
                size_t pcrSelectionBytesLength,
                const uint8_t* qualifyingDataBytes,
                size_t qualifyingDataBytesLength,
                uint8_t** const quoteBytes, 
                int* const quoteBytesLength)
{
    TSS2_RC             rval;
    TPM2B_AUTH          aikPassword = {0};                                      // For getting the qoute 
    TPM2B_ATTEST        quote = TPM2B_TYPE_INIT(TPM2B_ATTEST, attestationData); // quote data from TPM
    TPMT_SIGNATURE      signature = {0};                                        // signature data from TPM
    TPML_PCR_SELECTION* pcrSelection;                                           // which banks/pcrs to collect (from HVS request)
    TPM2B_DATA          qualifyingData = {0};                                   // the 'nonce' from HVS
    TPML_DIGEST         pcrMeasurements[DEFAULT_PCR_MEASURMENT_COUNT] = {0};    // pcr measurements from TPM
    size_t              pcrsCollectedCount = 0;                                 // number of pcr measurements collected

    // KWT: the aik is required on rhel8, but fails when set in the simulator
    rval = InitializeTpmAuth(&aikPassword, aikSecretKey, aikSecretKeyLength);
    if(rval != 0)
    {
        ERROR("There was an error creating the aik TPM2B_AUTH");
        return rval;
    }

    if (pcrSelectionBytes == NULL || pcrSelectionBytesLength == 0 || pcrSelectionBytesLength > sizeof(TPML_PCR_SELECTION))
    {
        ERROR("Invalid pcrselection parameter");
        return -1;
    }

    pcrSelection = (TPML_PCR_SELECTION*)pcrSelectionBytes;

    if (qualifyingDataBytes == NULL || qualifyingDataBytesLength == 0 || qualifyingDataBytesLength > ARRAY_SIZE(qualifyingData.buffer))
    {
        ERROR("Invalid qualifying data parameter");
        return -1;
    }

    qualifyingData.size = qualifyingDataBytesLength;
    memcpy(&qualifyingData.buffer, qualifyingDataBytes, qualifyingDataBytesLength);

    //
    // get the quote and signature information.  check results
    //
    rval = getQuote(ctx->sys, 
                    &aikPassword,       
                    TPM_HANDLE_AIK,     // KWT: don't pass, move to getQuote
                    pcrSelection, 
                    &qualifyingData, 
                    &quote, 
                    &signature);

    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    // validate the quote data returned from getQuote
    if(quote.size == 0 || quote.size > ARRAY_SIZE(quote.attestationData)) 
    {
         ERROR("Incorrect quote buffer size: 0x%x", quote.size)
         return -1;   
    }

    // validate the signature data returned from getQuote
    if(signature.signature.rsassa.sig.size == 0 || signature.signature.rsassa.sig.size > ARRAY_SIZE(signature.signature.rsassa.sig.buffer)) 
    {
         ERROR("Incorrect signature buffer size: 0x%x", signature.signature.rsassa.sig.size)
         return -1;   
    }

    //
    // get the pcr measurements
    //
    rval = getPcrs(ctx->sys, 
                   pcrSelection,      
                   pcrMeasurements,
                   &pcrsCollectedCount);

    if (rval != TSS2_RC_SUCCESS)
    {
        return rval;
    }

    // validate the number or pcrs collected from getPcrs
    if (pcrsCollectedCount <=0 || pcrsCollectedCount > 24)
    {
         ERROR("Unexpected amount of pcrs collected: 0x%lx", pcrsCollectedCount)
         return -1;   
    }

    return CreateQuoteBuffer(&quote, &signature, pcrSelection, pcrMeasurements, quoteBytes, quoteBytesLength);
}
