/*
 * Copyright (C) 2024-2025 Intel Corporation
 * SPDX-License-Identifier: MIT-0
 */

/**
 *
 * @file fcs_osal_types.h
 * @brief contains OS abstraction layer data types for linux_aarch64 platform.
 */

#ifndef LIBFCS_OSAL_TYPES_H
#define LIBFCS_OSAL_TYPES_H

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
