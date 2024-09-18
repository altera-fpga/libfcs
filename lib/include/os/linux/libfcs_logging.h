/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs_logging.h
 * @brief logging API used inside LibFCS
 */

#ifndef LIBFCS_LOGGING_H
#define LIBFCS_LOGGING_H

#include <libfcs_osal.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief FCS log levels
 *
 */
enum fcs_loglevel {
	L_LOG_OFF = 0,
	L_LOG_ERR = 1,
	L_LOG_WRN = 2,
	L_LOG_INF = 3,
	L_LOG_DBG = 4,
	L_LOG_MAX
};

/**
 * @brief default log level
 *
 */
#ifndef L_LOG_LVL
#define L_LOG_LVL L_LOG_INF
#endif

/** debug log API */
#define FCS_LOG_DBG(format, ...) fcs_logger(L_LOG_DBG, format, ##__VA_ARGS__)
/** info log API */
#define FCS_LOG_INF(format, ...) fcs_logger(L_LOG_INF, format, ##__VA_ARGS__)
/** warn log API */
#define FCS_LOG_WRN(format, ...) fcs_logger(L_LOG_WRN, format, ##__VA_ARGS__)
/** error log API */
#define FCS_LOG_ERR(format, ...) fcs_logger(L_LOG_ERR, format, ##__VA_ARGS__)

/**
 * @brief set logging level of logger system
 *
 * @param level logging level
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_set_logging(enum fcs_loglevel level);

/**
 * @brief initialize logging
 *
 * @param log_file file to log the messages.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_logging_init(FCS_OSAL_CHAR *log_file);

/**
 * @brief logging function each platform needs to define
 *
 * @param level logging level
 * @param format string format
 *
 * @return Nil
 */
FCS_OSAL_VOID fcs_logger(enum fcs_loglevel level, const FCS_OSAL_CHAR *format, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBFCS_LOGGING_H */
