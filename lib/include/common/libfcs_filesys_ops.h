/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs_filesys_ops.h
 * @brief OS Abstraction API's for filesys operation used inside LibFCS.
 */

#ifndef LIBFCS_FILESYS_OPS_H
#define LIBFCS_FILESYS_OPS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <libfcs_osal.h>

/**
 * @brief FCS flags for file operations.
 */
typedef enum {
	/** file read operation*/
	FCS_FILE_READ,
	/** file write operation*/
	FCS_FILE_WRITE,
	/** file append operation*/
	FCS_FILE_APPEND
} fcs_filesys_flags_t;

/**
 * @brief FCS flags for moving file pointer.
 */
typedef enum {
	/** set relative to start*/
	FCS_SEEK_SET,
	/** set relative to current pointer*/
	FCS_SEEK_CUR,
	/** set relative to end of file*/
	FCS_SEEK_END
} fcs_filesys_whence_t;

/**
 * @brief typedef open function for opening a file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[in] filename path to the file in the system.
 * @param[in] flag file operation flag as per @ref fcs_filesys_flags_t.
 * @return pointer to file object, NULL if error.
 */
typedef FCS_OSAL_FILE *(*file_open_t)(FCS_OSAL_CHAR *filename, fcs_filesys_flags_t flag);

/**
 * @brief typedef read function to read a chunk from a opened file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[out] buf pointer to buffer to which the file contents are copied into.
 * @param[in] len number of bytes to be read from file.
 * @param[in] file pointer to file object which was returned from open function.
 * @return number of bytes read from file, negative number on error.
 */
typedef FCS_OSAL_INT (*file_read_t)(FCS_OSAL_VOID *buf, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file);

/**
 * @brief typedef write function to write a chunk to a opened file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[in] buf pointer to buffer from which the contents are written to the file.
 * @param[in] len number bytes to be written.
 * @param[in] file pointer to file object returned from open function.
 * @return number of bytes written to file, negative number on error.
 */
typedef FCS_OSAL_INT (*file_write_t)(FCS_OSAL_VOID *buf, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file);

/**
 * @brief typedef fgets function to read a string of characters from a file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[out] str pointer to a string buffer to which the read characters are stored.
 * @param[in] len length of buffer.
 * @param[in] file pointer to file object returned from open function.
 * @return 0 on success, 1 on reaching end of file, negative number on error.
 */
typedef FCS_OSAL_INT (*file_fgets_t)(FCS_OSAL_CHAR *str, FCS_OSAL_SIZE len, FCS_OSAL_FILE *file);

/**
 * @brief typedef fseek function to move the file pointer on an opened file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[in] offset relative position to the desired location.
 * @param[in] whence base location from which the relative offset is calculated. @ref fcs_filesys_whence_t.
 * @param[in] file pointer to file object returned from open function.
 * @return 0 on success, negative number on error.
 */
typedef FCS_OSAL_INT (*file_fseek_t)(FCS_OSAL_OFFSET offset, fcs_filesys_whence_t whence,
				FCS_OSAL_FILE *file);

/**
 * @brief typedef close function to close an opened file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[in] file pointer to file object returned from open function.
 * @return 0 on success, negative number on error.
 */
typedef FCS_OSAL_INT (*file_close_t)(FCS_OSAL_FILE *file);

/**
 * @brief typedef get size function to get the size of a file.
 *
 * @note needs to be populated for all platforms.
 *
 * @param[in] file pointer to file object returned from open function.
 * @param[out] size pointer to the size of the file.
 * @return zero on success, negative number on error.
 *
 */
typedef FCS_OSAL_INT (*file_get_size_t)(FCS_OSAL_FILE *file, FCS_OSAL_SIZE *size);

/**
 * @brief file system interface structure which needs to be populated @see fcs_filesys_init().
 */

 struct fcs_filesys_intf {
	/** file open function pointer*/
	file_open_t open;
	/** file read function pointer*/
	file_read_t read;
	/** file write function pointer*/
	file_write_t write;
	/** file fgets function pointer*/
	file_fgets_t fgets;
	/** file fseek function pointer*/
	file_fseek_t fseek;
	/** file close function pointer*/
	file_close_t close;
	/** file get size function pointer */
	file_get_size_t get_size;
};
/**
 * @brief Initialize the file system interface.
 *
 * @param[in] filesys_intf pointer to the file system interface structure.
 *
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_filesys_init(struct fcs_filesys_intf *filesys_intf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
