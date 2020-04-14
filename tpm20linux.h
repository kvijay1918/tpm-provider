/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

// This file contains all of the tss2 specific functions, defines, etc. to
// support tpm20linux.go

#ifndef __TPM_20_LINUX__
#define __TPM_20_LINUX__


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2-tcti-tabrmd.h>
#include <tss2/tss2_tcti_device.h>

#include "tpm.h"

#define TRUE 1
#define FALSE 0

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(*array))

// from https://github.com/tpm2-software/tpm2-tools/blob/3.1.0/lib/tpm2_util.h
#define BUFFER_SIZE(type, field) (sizeof((((type *)NULL)->field)))
#define TPM2B_TYPE_INIT(type, field) { .size = BUFFER_SIZE(type, field), }
#define TPM2B_INIT(xsize) { .size = xsize, }
#define TPM2B_EMPTY_INIT TPM2B_INIT(0)

#define TPMT_TK_CREATION_EMPTY_INIT { \
        .tag = 0, \
		.hierarchy = 0, \
		.digest = TPM2B_EMPTY_INIT \
    }

#define TPM2B_SENSITIVE_CREATE_EMPTY_INIT { \
           .sensitive = { \
                .data.size = 0, \
                .userAuth.size = 0, \
            }, \
    }

#define TPMS_AUTH_COMMAND_INIT(session_handle) { \
        .sessionHandle = session_handle,\
	    .nonce = TPM2B_EMPTY_INIT, \
	    .sessionAttributes = 0, \
	    .hmac = TPM2B_EMPTY_INIT \
    }

#define PUBLIC_AREA_TPMA_OBJECT_DEFAULT_INIT { \
    .publicArea = { \
        .type = TPM2_ALG_RSA, \
        .objectAttributes = \
            TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT \
            |TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT \
            |TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH \
        , \
    }, \
}    

#define TPM2_ERROR_TSS2_RC_ERROR_MASK 0xFFFF

/*
 * This macro is useful as a wrapper around SAPI functions to automatically
 * retry function calls when the RC is TPM2_RC_RETRY.
 */
#define TSS2_RETRY_EXP(expression)                         \
    ({                                                     \
        TSS2_RC __result = 0;                              \
        do {                                               \
            __result = (expression);                       \
        } while ((__result & TPM2_ERROR_TSS2_RC_ERROR_MASK) == TPM2_RC_RETRY); \
        __result;                                          \
    })

#define LOG(fmt, ...) fprintf(stdout, "[LOG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);
#define ERROR(fmt, ...) fprintf(stderr, "[ERR:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);

#define ENABLE_DEBUG_LOGGING 0
#if ENABLE_DEBUG_LOGGING
#define DEBUG(fmt, ...) fprintf(stdout, "[DBG:%s::%d] " fmt "\n", __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__);
#else
#define DEBUG(fmt, ...)
#endif

struct tpmCtx
{
    TPM_VERSION version;
    TSS2_TCTI_CONTEXT* tcti;
    TSS2_SYS_CONTEXT* sys;
};

// util.c
int InitializeTpmAuth(TPM2B_AUTH* auth, const char* secretKey, size_t secretKeyLength);
int ClearKeyHandle(TSS2_SYS_CONTEXT *sys, TPM2B_AUTH *ownerAuth, TPM_HANDLE keyHandle);

#endif