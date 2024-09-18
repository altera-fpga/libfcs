/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file fcs_osal_types.h
 * @brief contains OS abstraction layer data types for linux_aarch64 platform.
 */

#ifndef FCS_OSAL_TYPES_H
#define FCS_OSAL_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include <stdio.h>
#include <stdint.h>
#include <linux/types.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>

#define FCS_GENERIC_ERR 0xff
#define FCS_OSAL_UUID_SIZE (16U)
#define FCS_OSAL_MAX_RESP_STATUS_SIZE (4U)
#define FCS_AES_CRYPT_BLOCK_SIZE (16U)
#define FCS_CIPHER_NAME_MAX_SIZE (32U)

#define FCS_AES_BLOCK_MODE_ECB 0
#define FCS_AES_BLOCK_MODE_CBC 1
#define FCS_AES_BLOCK_MODE_CTR 2
#define FCS_AES_BLOCK_MODE_GCM 3
#define FCS_AES_BLOCK_MODE_GHASH 4
#define FCS_MAX_AES_CRYPT_MODE 5

#define FCS_AES_GCM_MAX_AAD_SIZE 65535
#define FCS_AES_GCM_TAG_SIZE 3

#define FCS_AES_IV_SOURCE_INTERNAL 1
#define FCS_AES_IV_SOURCE_EXTERNAL 0

#define FCS_AES_ENCRYPT 0
#define FCS_AES_DECRYPT 1

#define FCS_ECC_CURVE_NIST_P256 1
#define FCS_ECC_CURVE_NIST_P384 2
#define FCS_ECC_CURVE_BRAINPOOL_P256 3
#define FCS_ECC_CURVE_BRAINPOOL_P384 4
#define FCS_ECC_CURVE_MASK 0x4

#define FCS_ECDH_P256_PUBKEY_LEN 64
#define FCS_ECDH_P384_PUBKEY_LEN 96
#define FCS_ECDH_BP256_PUBKEY_LEN 64
#define FCS_ECDH_BP384_PUBKEY_LEN 96
#define FCS_ECDH_P256_SECRET_LEN 32
#define FCS_ECDH_P384_SECRET_LEN 48
#define FCS_ECDH_BP256_SECRET_LEN 32
#define FCS_ECDH_BP384_SECRET_LEN 48

#define FCS_SHA_384 1
#define FCS_SHA_384_DIGEST_SIZE 48
#define FCS_CERT_LEN_PARAM_SZ	sizeof(uint32_t)

/** unsigned 64 bit*/
typedef __u64 FCS_OSAL_U64;
/** unsigned 32 bit*/
typedef __u32 FCS_OSAL_U32;
/** unsigned 16 bit*/
typedef __u16 FCS_OSAL_U16;
/** unsigned 8 bit*/
typedef __u8 FCS_OSAL_U8;

/** signed 64 bit*/
typedef __s64 FCS_OSAL_S64;
/** signed 32 bit*/
typedef __s32 FCS_OSAL_S32;
/** unsigned 16 bit*/
typedef __s16 FCS_OSAL_S16;
/** unsigned 8 bit*/
typedef __s8 FCS_OSAL_S8;

/** void type*/
typedef void FCS_OSAL_VOID;
/** character data type*/
typedef char FCS_OSAL_CHAR;
/** Unsigned character data type*/
typedef unsigned char FCS_OSAL_UCHAR;
/** boolean data type*/
typedef bool FCS_OSAL_BOOL;

/** integer data type*/
typedef int FCS_OSAL_INT;
/** unsigned integer data type*/
typedef unsigned int FCS_OSAL_UINT;
/** data type to denote offset */
typedef off_t FCS_OSAL_OFFSET;
/** data type to denote size*/
typedef size_t FCS_OSAL_SIZE;

/** mutex object type*/
typedef pthread_mutex_t FCS_OSAL_MUTEX;
/** file object type*/
typedef FILE FCS_OSAL_FILE;
/** integer data type uuid for session ids*/
typedef char FCS_OSAL_UUID;

// TODO:  which data type
typedef int FCS_OSAL_ERROR;

// TODO: which data type
typedef int FCS_OSAL_RSIZE;

typedef uintptr_t FCS_OSAL_UINTPTR;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
