/* SPDX-License-Identifier: MIT-0 */
/* Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs_logging.h
 * @brief logging API used inside LibFCS
 */

#ifndef LIBFCS_LOGGING_H
#define LIBFCS_LOGGING_H

#include <libfcs_osal.h>
#include <zephyr/logging/log.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


/**
 * @brief integrate FCS logging with zephyr logging system.
 *
 */
LOG_MODULE_DECLARE(LibFCS, CONFIG_LIBFCS_LOG_LEVEL);

#undef FCS_LOG_DBG
#define FCS_LOG_DBG(format, ...) LOG_DBG(format, ##__VA_ARGS__)

#undef FCS_LOG_INF
#define FCS_LOG_INF(format, ...) LOG_INF(format, ##__VA_ARGS__)

#undef FCS_LOG_WRN
#define FCS_LOG_WRN(format, ...) LOG_WRN(format, ##__VA_ARGS__)

#undef FCS_LOG_ERR
#define FCS_LOG_ERR(format, ...) LOG_ERR(format, ##__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBFCS_LOGGING_H */
