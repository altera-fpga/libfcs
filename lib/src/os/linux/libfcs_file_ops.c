/*
 * Copyright (C) 2025 Altera
 * SPDX-License-Identifier: MIT-0
 */
#include <libfcs_filesys_ops.h>
#include <libfcs_logging.h>
#include <string.h>
#include <errno.h>

static FCS_OSAL_FILE *fcs_linux_filesys_open(FCS_OSAL_CHAR *filename,
					     fcs_filesys_flags_t flag)
{
	if (!filename) {
		FCS_LOG_ERR("invalid argument\n");
		return NULL;
	}

	FCS_OSAL_FILE *file;

	errno = 0;

	if (flag == FCS_FILE_READ) {
		file = fopen(filename, "r");
	} else if (flag == FCS_FILE_WRITE) {
		file = fopen(filename, "w+");
	} else if (flag == FCS_FILE_APPEND) {
		file = fopen(filename, "a+");
	} else {
		FCS_LOG_ERR("invalid argument in flag\n");
		return NULL;
	}

	if (errno) {
		FCS_LOG_ERR("error in opening file with error : %d\n", errno);
		return NULL;
	}

	return file;
}

static FCS_OSAL_INT fcs_linux_filesys_read(FCS_OSAL_VOID *buf, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file)
{
	if (!buf || len <= 0 || !file) {
		return -EINVAL;
	}

	FCS_OSAL_INT ret = fread(buf, 1, len, file);
	if (ret < 0) {
		FCS_LOG_ERR("error in reading the file %d", errno);
	}
	return ret;
}

static FCS_OSAL_INT fcs_linux_filesys_write(FCS_OSAL_VOID *buf, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file)
{
	if (!buf || len <= 0 || !file) {
		return -EINVAL;
	}

	FCS_OSAL_INT ret = fwrite(buf, 1, len, file);
	if (ret < 0) {
		FCS_LOG_ERR("error in writing to file %d", errno);
	}
	return ret;
}

static FCS_OSAL_INT fcs_linux_filesys_fseek(FCS_OSAL_OFFSET offset, fcs_filesys_whence_t whence,
	FCS_OSAL_FILE *file)
{
	if (!file) {
		return -EINVAL;
	}

	FCS_OSAL_INT ret = 0;
	if (whence == FCS_SEEK_SET) {
		ret = fseek(file, offset, SEEK_SET);
	} else if (whence == FCS_SEEK_CUR) {
		ret = fseek(file, offset, SEEK_CUR);
	} else if (whence == FCS_SEEK_END) {
		ret = fseek(file, offset, SEEK_END);
	} else {
		FCS_LOG_ERR("invalid whence %d\n", whence);
		return -EINVAL;
	}

	if (errno) {
		FCS_LOG_ERR("error in fseek : %s", strerror(errno));
	}

	return ret;
}

static FCS_OSAL_INT fcs_linux_filesys_fgets(FCS_OSAL_CHAR *str, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file)
{
	if (str == NULL || len == 0 || file == NULL) {
		return -EINVAL;
	}

	FCS_OSAL_CHAR *ptr;
	errno = 0;
	ptr = fgets(str, len, file);
	if (ptr == NULL && errno == 0) {
		return 1;
	} else if (errno != 0) {
		return -errno;
	} else {
		return 0;
	}
}

static FCS_OSAL_INT fcs_linux_filesys_close(FCS_OSAL_FILE *file)
{
	if (!file) {
		return -EINVAL;
	}
	FCS_OSAL_INT ret = fclose(file);
	if (ret) {
		FCS_LOG_ERR("error in closing the file %d", ret);
		return ret;
	}
	return ret;
}

static FCS_OSAL_INT fcs_filesys_get_size(FCS_OSAL_FILE *file, FCS_OSAL_SIZE *size)
{
	struct stat file_stat;

	if (!file || !size) {
		FCS_LOG_ERR("Invalid file pointer or size pointer\n");
		return -EINVAL;
	}

	int fd = fileno(file);
	if (fd < 0) {
		FCS_LOG_ERR("Failed to get file descriptor");
		return -errno;
	}

	if (fstat(fd, &file_stat) < 0) {
		FCS_LOG_ERR("Failed to get file stats");
		return -errno;
	}

	*size = file_stat.st_size;
	if (*size == 0) {
		FCS_LOG_ERR("error in fstat : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

FCS_OSAL_INT fcs_filesys_init(struct fcs_filesys_intf *filesys_intf)
{
	if (!filesys_intf) {
		return -EINVAL;
	}
	filesys_intf->open = fcs_linux_filesys_open;
	filesys_intf->read = fcs_linux_filesys_read;
	filesys_intf->fgets = fcs_linux_filesys_fgets;
	filesys_intf->write = fcs_linux_filesys_write;
	filesys_intf->fseek = fcs_linux_filesys_fseek;
	filesys_intf->close = fcs_linux_filesys_close;
	filesys_intf->get_size = fcs_filesys_get_size;
	return 0;
}
