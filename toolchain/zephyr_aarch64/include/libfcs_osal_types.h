/*
 * Copyright (C) 2024-2025 Intel Corporation
 * SPDX-License-Identifier: MIT-0
 */

/**
 *
 * @file fcs_osal_types.h
 * @brief contains OS abstraction layer data types for zephyr platform.
 */

#ifndef FCS_OSAL_TYPES_H
#define FCS_OSAL_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <zephyr/kernel.h>
#include <sys/types.h>
#include <stddef.h>
#include <errno.h>

#define PLATFORM_ZEPHYR 1

/** unsigned 64 bit*/
typedef uint64_t FCS_OSAL_U64;
/** unsigned 32 bit*/
typedef uint32_t FCS_OSAL_U32;
/** unsigned 16 bit*/
typedef uint16_t FCS_OSAL_U16;
/** unsigned 8 bit*/
typedef uint8_t FCS_OSAL_U8;

/** signed 64 bit*/
typedef int64_t FCS_OSAL_S64;
/** signed 32 bit*/
typedef int32_t FCS_OSAL_S32;
/** unsigned 16 bit*/
typedef int16_t FCS_OSAL_S16;
/** unsigned 8 bit*/
typedef int8_t FCS_OSAL_S8;

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
typedef struct k_mutex FCS_OSAL_MUTEX;
/** file object type*/
typedef struct fs_file_t FCS_OSAL_FILE;
/** integer data type uuid for session ids*/
typedef char FCS_OSAL_UUID;

// TODO:  which data type
typedef int FCS_OSAL_ERROR;

// TODO: which data type
typede int FCS_OSAL_RSIZE;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
