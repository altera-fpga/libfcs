// SPDX-License-Identifier: MIT-0
/*
 * Copyright (C) 2025 Altera
 */
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libfcs_utils.h>
#include <libfcs_logging.h>

#define FCS_FILE_OP_BUF_SIZE	(256U)

FCS_OSAL_INT put_devattr(const FCS_OSAL_CHAR *fcs_dev,
			 const FCS_OSAL_CHAR *attr, FCS_OSAL_CHAR *buffer,
			 FCS_OSAL_U32 size)
{
	int fd;
	ssize_t ret;
	FCS_OSAL_CHAR *sysfs_name = NULL;

	if (!fcs_dev || !attr || !buffer || !size) {
		FCS_LOG_ERR("error: invalid input\n");
		return -EINVAL;
	}

	sysfs_name = (FCS_OSAL_CHAR *)fcs_malloc(FCS_FILE_OP_BUF_SIZE);
	if (!sysfs_name) {
		FCS_LOG_ERR("error: failed to alloc sysfs buffer\n");
		return -ENOMEM;
	}

	memset(sysfs_name, 0, FCS_FILE_OP_BUF_SIZE);
	snprintf(sysfs_name, FCS_FILE_OP_BUF_SIZE, "%s/%s", fcs_dev, attr);

	FCS_LOG_DBG("sysfs attribute %s\n", sysfs_name);

	fd = open(sysfs_name, O_WRONLY);
	if (fd < 0) {
		FCS_LOG_ERR("Failed to open sysfs attribute for writing %s\n",
			    sysfs_name);
		free(sysfs_name);
		return -EBADF;
	}

	ret = write(fd, buffer, size);
	if (ret < 0) {
		FCS_LOG_ERR("Failed to write to sysfs attribute");
		free(sysfs_name);
		close(fd);
		return -EACCES;
	}

	close(fd);

	free(sysfs_name);
	return 0;
}
