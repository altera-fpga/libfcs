// SPDX-License-Identifier: MIT-0
/*
 * Copyright (C) 2025 Altera
 */

#include <libfcs_osal.h>
#include <libfcs_logging.h>
#include <libfcs_utils.h>
#include <string.h>
#include <stdarg.h>

enum fcs_loglevel fcs_curr_loglevel = L_LOG_LVL;

FCS_OSAL_INT fcs_set_logging(enum fcs_loglevel level)
{
	if (level >= L_LOG_MAX) {
		FCS_LOG_ERR("wrong log level provided : %d", level);
		return -EINVAL;
	}
	fcs_curr_loglevel = level;
	return 0;
}

FCS_OSAL_INT fcs_logging_init(FCS_OSAL_CHAR *loglevel)
{
	if (loglevel == NULL) {
		fcs_set_logging(L_LOG_WRN);
		FCS_LOG_INF("No log level provided, setting to default as log_inf");
		return -EINVAL;
	}

	if (strcmp(loglevel, "log_off") == 0)
		fcs_set_logging(L_LOG_OFF);
	else if (strcmp(loglevel, "log_err") == 0)
		fcs_set_logging(L_LOG_ERR);
	else if (strcmp(loglevel, "log_wrn") == 0)
		fcs_set_logging(L_LOG_WRN);
	else if (strcmp(loglevel, "log_inf") == 0)
		fcs_set_logging(L_LOG_INF);
	else if (strcmp(loglevel, "log_dbg") == 0)
		fcs_set_logging(L_LOG_DBG);

	return 0;
}

FCS_OSAL_VOID fcs_logger(enum fcs_loglevel level, const FCS_OSAL_CHAR *format, ...)
{
	const FCS_OSAL_CHAR *l_log[] = {"", "err:", "wrn:", "inf:", "dbg:"};
	va_list arg;

	if (level == L_LOG_OFF || level > fcs_curr_loglevel)
		return;

	fprintf(stderr, "\n[%s]", l_log[level]);
	fflush(stderr);
	va_start(arg, format);
	vfprintf(stderr, format, arg);
	va_end(arg);
	fflush(stderr);
}

#define FCS_LOG_DBG(format, ...) fcs_logger(L_LOG_DBG, format, ##__VA_ARGS__)
#define FCS_LOG_ERR(format, ...) fcs_logger(L_LOG_ERR, format, ##__VA_ARGS__)
