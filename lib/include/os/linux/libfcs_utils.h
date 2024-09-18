/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs_utils.h
 * @brief utility functions used inside LibFCS
 */

#ifndef LIBFCS_UTILS_H
#define LIBFCS_UTILS_H

#include <libfcs_osal.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef ARG_UNUSED
/** unused argument placater*/
#define ARG_UNUSED(x) ((void)(x))
#endif

/**
 * @brief Get device attribute
 *
 * @param fcs_dev device name
 * @param attr attribute name
 * @param buffer to store attribute value
 * @param size buffer size
 * @return 0 on success, -1 on error
 */
FCS_OSAL_INT get_devattr(const FCS_OSAL_CHAR *fcs_dev,
			 const FCS_OSAL_CHAR *attr, FCS_OSAL_CHAR *buffer,
			 FCS_OSAL_U32 size);

/**
 * @brief Put device attribute
 *
 * @param fcs_dev device name
 * @param attr attribute name
 * @param buffer to store attribute value
 * @param size buffer size
 * @return 0 on success, -1 on error
 */
FCS_OSAL_INT put_devattr(const FCS_OSAL_CHAR *fcs_dev,
			 const FCS_OSAL_CHAR *attr, FCS_OSAL_CHAR *buffer,
			 FCS_OSAL_U32 size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
