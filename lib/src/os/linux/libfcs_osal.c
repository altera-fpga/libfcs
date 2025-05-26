// SPDX-License-Identifier: MIT-0
/*
 * Copyright (C) 2025 Altera
 */

/**
 * @file libfcs_osal.c
 * @brief Implementation of the OS Abstraction Layer (OSAL) functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <kcapi.h>
#include <libfcs_osal.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <libfcs_logging.h>
#include <libfcs_utils.h>
#include <libfdt.h>

#define LIB_FCS_DEFAULT_RANDOM_NUMBER_SIZE		(8)
#define FCS_DEV_BUF_SIZE				(256)
#define FCS_COUNTER_SET_TIMEOUT				(1000)
#define FCS_OPEN_SESSION_TIMEOUT			(1000)
#define FCS_CLOSE_SESSION_TIMEOUT			(1000)
#define FCS_SUCCESS_RESPONSE				(1)
#define FCS_FAILURE_RESPONSE				(-1)
#define CRYPTO_DIGEST_MAX_SZ				0x00400000

#ifndef DEFAULT_SYS_DIR
#define DEFAULT_SYS_DIR "/sys/kernel/fcs_sysfs"
#endif

static FCS_OSAL_CHAR fcs_dev_local[FCS_DEV_BUF_SIZE + 1] = DEFAULT_SYS_DIR;

static FCS_OSAL_INT fcs_linux_api_binding(struct libfcs_osal_intf *intf);
static FCS_OSAL_INT fcs_linux_kcpai_init(FCS_OSAL_CHAR *loglevel);
static FCS_OSAL_INT fcs_linux_open_service_session(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_close_service_session(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_random_number_ext(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_import_service_key(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_export_service_key(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_remove_service_key(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_service_key_info(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_create_service_key(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_service_get_provision_data(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_counter_set(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_counter_set_preauthorized(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_hkdf_request(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_aes_crypt(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdh_req(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_digest(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mac_verify(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_sdos_encrypt(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_sdos_decrypt(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_chip_id(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_attestation_get_certificate(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_attestation_cert_reload(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mctp_cmd_send(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_jtag_idcode(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_device_identity(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_open(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_close(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_set_cs(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_read(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_write(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_qspi_erase(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_get_pub_key(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_hash_sign(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_hash_verify(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_sha2_data_sign(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_ecdsa_sha2_data_verify(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_hps_img_validate(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mbox_send_cmd(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_data_sign_init(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_ecdsa_data_sign_update(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_ecdsa_data_sign_final(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_ecdsa_data_verify_init(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_ecdsa_data_verify_update(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT
fcs_linux_ecdsa_data_verify_final(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_aes_crypt_init(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_aes_crypt_update(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_aes_crypt_final(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_digest_init(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_digest_update(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_get_digest_final(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mac_verify_init(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mac_verify_update(struct fcs_cmd_context *ctx);
static FCS_OSAL_INT fcs_linux_mac_verify_final(struct fcs_cmd_context *ctx);

/**
 * @brief Allocate memory of given size.
 *
 * @param size allocate memory size.
 * @return Pointer to the allocated memory, or NULL if size is 0 or allocation
 * fails.
 */
FCS_OSAL_VOID *fcs_malloc(FCS_OSAL_SIZE size)
{
	if (size == 0) {
		FCS_LOG_ERR("Attempted to allocate zero size memory\n");
		return NULL;
	}
	FCS_OSAL_VOID *ptr = malloc(size);

	if (!ptr)
		FCS_LOG_ERR("Memory allocation failed\n");

	return ptr;
}

/**
 * @brief Free allocated memory.
 *
 * @param ptr Pointer to the memory to free.
 */
FCS_OSAL_VOID fcs_osal_free(FCS_OSAL_VOID *ptr)
{
	if (ptr)
		free(ptr);
	else
		FCS_LOG_WRN("Attempted to free a NULL pointer\n");
}

/**
 * @brief Initialize a mutex.
 *
 * @param mutex Pointer to the mutex.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_mutex_init(FCS_OSAL_MUTEX *mutex)
{
	if (!mutex) {
		FCS_LOG_ERR("Invalid mutex pointer provided to fcs mutex init\n");
		return -EINVAL;
	}

	FCS_OSAL_INT ret = pthread_mutex_init(mutex, NULL);

	if (ret != 0)
		FCS_LOG_ERR("Mutex initialization failed with error: %d\n", ret);

	return ret;
}

/**
 * @brief Lock the mutex with a timeout.
 *
 * @param mutex Pointer to the mutex.
 * @param time Timeout value in milliseconds.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_mutex_timedlock(FCS_OSAL_MUTEX *mutex, FCS_OSAL_U32 const time)
{
	FCS_OSAL_INT ret = -1;

	/* Check if the mutex pointer is NULL */
	if (!mutex) {
		FCS_LOG_ERR("Invalid mutex pointer provided to fcs mutex timedlock\n");
		return -EINVAL; // Return invalid argument error
	}

	/* Handle special time values */
	if (time == FCS_TIME_FOREVER) {
		/* Wait indefinitely for the mutex */
		ret = pthread_mutex_lock(mutex);
	} else if (time == FCS_TIME_NOWAIT) {
		/* Try to lock the mutex without waiting */
		ret = pthread_mutex_trylock(mutex);
	} else {
		/* Calculate the wait time in seconds and nanoseconds */
		struct timespec wait;

		wait.tv_sec = (time / 1000); /* Convert milliseconds to seconds */
		wait.tv_nsec = (time % 1000) * 1000000; /* Convert remaining ms to ns */

		/* Attempt to lock the mutex with a timeout */
		ret = pthread_mutex_timedlock(mutex, &wait);
	}

	return ret;
}

/**
 * @brief Release the mutex.
 *
 * @param mutex Pointer to the mutex.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_mutex_unlock(FCS_OSAL_MUTEX *mutex)
{
	/* Check if the mutex pointer is NULL */
	if (!mutex) {
		FCS_LOG_ERR("Invalid mutex pointer provided to fcs mutex unlock\n");
		return -EINVAL; /* Return invalid argument error */
	}

	/* Unlock the mutex */
	FCS_OSAL_INT ret = pthread_mutex_unlock(mutex);

	if (ret != 0)
		FCS_LOG_ERR("Mutex unlock failed with error: %d\n", ret);

	return ret;
}

/**
 * @brief Destroy the mutex.
 *
 * @param mutex Pointer to the mutex.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_mutex_destroy(FCS_OSAL_MUTEX *mutex)
{
	/* Check if the mutex pointer is NULL */
	if (!mutex) {
		FCS_LOG_ERR("Invalid mutex pointer provided to fcs mutex destroy\n");
		return -EINVAL; /* Return invalid argument error */
	}

	/* Destroy the mutex */
	FCS_OSAL_INT ret = pthread_mutex_destroy(mutex);

	if (ret != 0)
		FCS_LOG_ERR("Mutex destroy failed with error: %d\n", ret);

	return ret;
}

/**
 * @brief allocate memory for the buffer and copy the file content to the buffer
 *
 * @param filename file name to read
 * @param buffer to copy the file content
 *
 * @return FCS_OSAL_INT
 */
FCS_OSAL_INT fcs_alloc_and_cpy_file_to_mem(const FCS_OSAL_CHAR *filename,
					   FCS_OSAL_CHAR **buffer)
{
	FCS_OSAL_FILE *file;
	FCS_OSAL_U32 read_size = 0;
	struct stat st;

	file = fopen(filename, "rbx");
	if (!file) {
		FCS_LOG_ERR("Unable to open file %s:  %s\n",
			    filename, strerror(errno));
		return -ENOENT;
	}

	/* Get the file statistics */
	if (fstat(fileno(file), &st)) {
		fclose(file);
		FCS_LOG_ERR("Unable to open file %s:  %s\n",
			    filename, strerror(errno));
		return -ENOENT;
	}

	*buffer = fcs_malloc(st.st_size);
	if (!*buffer) {
		FCS_LOG_ERR("Failed to allocate memory for file %s\n", filename);
		fclose(file);
		return -ENOMEM;
	}

	/* Read the HPS image */
	fseek(file, 0, SEEK_SET);
	read_size = fread(*buffer, 1, st.st_size, file);
	if (read_size != st.st_size) {
		FCS_LOG_ERR("Problem reading file into buffer %s: %s\n",
			    filename, strerror(errno));
		fcs_osal_free(*buffer);
		fclose(file);
		return -EIO;
	}

	fclose(file);
	return st.st_size;
}

/**
 * @brief prints debug information
 *
 * @param fit - pointer to the FIT image header
 * @param noffset - component image node offset
 * @param prop_name - fir node property name
 * @param err - error code
 */
static FCS_OSAL_VOID fcs_linux_fit_get_debug(const FCS_OSAL_VOID *fit,
					     FCS_OSAL_INT noffset,
					     FCS_OSAL_VOID *prop_name,
					     FCS_OSAL_INT err)
{
	FCS_LOG_DBG("Can't get '%s' property from FIT 0x%08lx, node: offset %d, name %s (%s)\n",
		    (FCS_OSAL_CHAR *)prop_name, (ulong)fit, noffset,
		    fdt_get_name(fit, noffset, NULL), fdt_strerror(err));
}

/**
 * @brief sanity check FIT image format.
 * runs a basic sanity FIT image verification.
 * Routine checks for mandatory properties, nodes, etc.
 *
 * @param fit - pointer to the FIT format image header
 *
 * @return 0, on success, EINVAL, on failure
 */
static FCS_OSAL_INT fcs_linux_fit_check_format(FCS_OSAL_CHAR *fit)
{
	/* mandatory / node 'description' property */
	if (!fdt_getprop(fit, 0, FIT_DESC_PROP, NULL)) {
		FCS_LOG_DBG("Wrong FIT format: no description\n");
		return -EINVAL;
	}

	if (IMAGE_ENABLE_TIMESTAMP) {
		/* mandatory / node 'timestamp' property */
		if (!fdt_getprop(fit, 0, FIT_TIMESTAMP_PROP, NULL)) {
			FCS_LOG_DBG("Wrong FIT format: no timestamp\n");
			return -EINVAL;
		}
	}

	/* mandatory subimages parent '/images' node */
	if (fdt_path_offset(fit, FIT_PARENT_NODE_PATH) < 0) {
		FCS_LOG_DBG("Wrong FIT format: no images parent node\n");
		return -EINVAL;
	}

	return 0;
}

/**
 * @brief Get the data pointer of the image in the FIT image
 *
 * @param fit - pointer to the FIT format image header
 * @param noffset - offset to the image node
 * @param data_size - pointer to store the data size
 *
 * @return 0 on success, other value on failure
 */
static FCS_OSAL_INT fcs_linux_fit_image_get_data_size(FCS_OSAL_CHAR *fit,
						      FCS_OSAL_INT noffset,
						      FCS_OSAL_INT *data_size)
{
	const FCS_OSAL_U32 *val;

	val = fdt_getprop((const FCS_OSAL_VOID *)fit, noffset,
			  FIT_DATA_SIZE_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_size = fdt32_to_cpu(*val);

	return 0;
}

/**
 * @brief Get the offset of the data in the FIT image
 *
 * @param fit - pointer to the FIT format image header
 * @param noffset - component image node offset
 * @param data_position - holds the data-position property
 *
 * @return 0 on success, other value on failure
 */
static FCS_OSAL_INT fcs_linux_fit_image_get_data_position(FCS_OSAL_CHAR *fit,
							  FCS_OSAL_INT noffset,
							  int *data_position)
{
	const FCS_OSAL_U32 *val;

	val = fdt_getprop((const FCS_OSAL_VOID *)fit, noffset,
			  FIT_DATA_POSITION_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_position = fdt32_to_cpu(*val);

	return 0;
}

/**
 * @brief Get 'data-offset' property from a given image node.
 *
 * @param fit - pointer to the FIT image header
 * @param noffset - component image node offset
 * @param data_offset - holds the data-offset property
 *
 * @return 0 on success, other value on failure
 */
static FCS_OSAL_INT
fcs_linux_fit_image_get_data_offset(FCS_OSAL_CHAR *fit, FCS_OSAL_INT noffset,
				    FCS_OSAL_INT *data_offset)
{
	const FCS_OSAL_U32 *val;

	val = fdt_getprop((const FCS_OSAL_VOID *)fit, noffset,
			  FIT_DATA_OFFSET_PROP, NULL);
	if (!val)
		return -ENOENT;

	*data_offset = fdt32_to_cpu(*val);

	return 0;
}

/**
 * @brief finds data property in a given component image node.
 * If the property is found its data start address and size are returned to
 * the caller.
 *
 * @param fit - pointer to the FIT image header
 * @param noffset - component image node offset
 * @param data - pointer to store the data pointer
 * @param size - pointer to store the data size
 *
 * @return 0 on success, other value on failure
 *
 */
static FCS_OSAL_INT fcs_linux_fit_img_get_data(const FCS_OSAL_VOID *fit,
						 FCS_OSAL_INT noffset,
						 const FCS_OSAL_VOID **data,
						 FCS_OSAL_SIZE *size)
{
	int len;

	*data = fdt_getprop(fit, noffset, FIT_DATA_PROP,
			    &len);
	if (!*data) {
		fcs_linux_fit_get_debug(fit, noffset, FIT_DATA_PROP, len);
		*size = 0;
		return -1;
	}

	*size = len;
	return 0;
}

/**
 * @brief returns fdt error message for the given error code
 */
const FCS_OSAL_CHAR *fcs_fit_strerror(FCS_OSAL_INT err)
{
	return fdt_strerror(err);
}

/**
 * @brief Verify the FIT image header.
 *
 * @param fit Pointer to the FIT buffer.
 * @param size FIT size.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_fit_verify_header(FCS_OSAL_CHAR *fit)
{
	if (!fdt_check_header((const FCS_OSAL_VOID *)fit) ||
	    !fcs_linux_fit_check_format(fit))
		return -1;
	return 0;
}

/**
 * @brief Get the position of the node in the FIT image
 *
 * @param fit - pointer to the FIT format image header
 * @param path - path to the node
 *
 * @return offset to the node
 */
FCS_OSAL_INT fcs_fit_get_noffset(FCS_OSAL_CHAR *fit, const FCS_OSAL_CHAR *path)
{
	return fdt_path_offset((const FCS_OSAL_VOID *)fit, path);
}

/**
 * @brief Get the next node in the FIT image
 *
 * @param fit - pointer to the FIT format image header
 * @param offset - offset to the node
 * @param depth - pointer to store the depth
 *
 * @return offset to the next node
 */
FCS_OSAL_INT fcs_fit_next_node(FCS_OSAL_CHAR *fit, FCS_OSAL_INT offset,
			       FCS_OSAL_INT *depth)
{
	return fdt_next_node((const FCS_OSAL_VOID *)fit, offset, depth);
}

/**
 * @brief Get the position of the data in the FIT image
 *
 * @param fit - pointer to the FIT format image header
 * @param noffset - offset to the image node
 * @param offset - pointer to store the data position
 * @param data - pointer to store the data pointer
 * @param size - pointer to store the data size
 *
 * @return 0 on success, other value on failure
 */
FCS_OSAL_INT fcs_fit_image_get_data_and_size(FCS_OSAL_CHAR *fit,
					     FCS_OSAL_INT noffset,
					     FCS_OSAL_CHAR **data,
					     FCS_OSAL_SIZE *size)
{
	bool external_data = false;
	int offset;
	int len = 0;
	int ret;

	if (!fcs_linux_fit_image_get_data_position(fit, noffset, &offset)) {
		external_data = true;
	} else if (!fcs_linux_fit_image_get_data_offset(fit, noffset, &offset)) {
		external_data = true;
		/*
		 * For FIT with external data, figure out where
		 * the external images start. This is the base
		 * for the data-offset properties in each image.
		 */
		offset += ((fdt_totalsize((const FCS_OSAL_VOID *)fit) + 3) & ~3);
	}

	if (external_data) {
		FCS_LOG_DBG("External Data\n");
		ret = fcs_linux_fit_image_get_data_size(fit, noffset, &len);
		*data = fit + offset;
		*size = len;
	} else {
		ret = fcs_linux_fit_img_get_data((const FCS_OSAL_VOID *)fit,
						noffset, (const FCS_OSAL_VOID **)data, size);
	}

	return ret;
}

/**
 * @brief Open a service session
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_open_service_session(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "open_session", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Close service session
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_close_service_session(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "close_session",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get provisioned data inforamtion
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT
fcs_linux_service_get_provision_data(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "prov_data", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Generate a random number
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_random_number_ext(struct fcs_cmd_context *ctx)
{
	struct kcapi_handle *handle = NULL;
	FCS_OSAL_INT ret;
	/* Initialize the RNG context */
	ret = kcapi_rng_init(&handle, "socfpga_rng", 0);
	if (ret < 0) {
		/* Check if the RNG initialization failed */
		FCS_LOG_ERR("Failed to initialize RNG: %s\n", strerror(-ret));
		return ret;
	}

	/* Send the open session command to the device */
	ret = put_devattr(fcs_dev_local, "context_info", (FCS_OSAL_CHAR *)&ctx,
			  sizeof(struct fcs_cmd_context *));
	if (ret != 0) {
		FCS_LOG_ERR("Failed to send open session command to the device: %s\n",
			    strerror(-ret));
		goto cleanup;
	}

	/* Generate random number */
	ret = kcapi_rng_generate(handle, (uint8_t *)ctx->rng.rng, ctx->rng.rng_len);
	if (ret < 0)
		FCS_LOG_ERR("Failed to generate random number: %s\n", strerror(-ret));
	else if ((FCS_OSAL_U32)ret == ctx->rng.rng_len)
		ret = 0;

cleanup:
	kcapi_rng_destroy(handle);
	return ret;
}

/**
 * @brief Import a service key
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_import_service_key(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "import_key", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Export a service key object
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_export_service_key(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "export_key", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Remove service key
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_remove_service_key(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "remove_key", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get service key information
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_service_key_info(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "key_info", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Create a service key
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_create_service_key(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "create_key", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform counter set
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_counter_set(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ctr_set", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform counter set preauth
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT
fcs_linux_counter_set_preauthorized(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ctr_set_preauth",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief HKDF request
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_hkdf_request(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "hkdf_req", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief AES cryptography operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_init(struct fcs_cmd_context *ctx);

/**
 * @brief AES cryptography operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_update(struct fcs_cmd_context *ctx);

/**
 * @brief AES cryptography operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_final(struct fcs_cmd_context *ctx);

/**
 * @brief Get chip ID
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_chip_id(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "chip_id", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get an attestation certificate
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT
fcs_linux_attestation_get_certificate(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "atstn_cert", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Attestation certificate reload
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT
fcs_linux_attestation_cert_reload(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "atstn_cert_reload",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform MCTP operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mctp_cmd_send(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "mctp_req", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get JTAG ID code
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_jtag_idcode(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "jtag_idcode", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get device identity
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_device_identity(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "device_identity",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Open an access to QSPI interface
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_open(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_open", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Close an access to QSPI interface
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_close(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_close", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Chip select
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_set_cs(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_cs", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Read data from QSPI flash
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_read(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_read", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Write data to QSPI flash
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_write(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_write", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Erase QSPI flash
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_qspi_erase(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "qspi_erase", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform AES encryption/decryption operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_aes_crypt(struct fcs_cmd_context *ctx)
{
	struct fcs_cmd_context *ctx_ptr = ctx;
	FCS_OSAL_INT ret = 0;

	ret = put_devattr(fcs_dev_local, "aes_crypt", (FCS_OSAL_CHAR *)&ctx_ptr,
			  sizeof(struct fcs_cmd_context *));
	if (ret != 0)
		*ctx_ptr->error_code_addr =
			ret; /* Return the error code from put_devattr */
	else if (*ctx_ptr->error_code_addr)
		FCS_LOG_ERR("Failed to set aes crypt context with sdm error code = %x\n",
			    *ctx_ptr->error_code_addr);

	return *ctx_ptr->error_code_addr;
}

static FCS_OSAL_INT fcs_linux_ecdh_req(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdh_req", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Generate digest
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "get_digest",
		(FCS_OSAL_CHAR *)&ctx,
		sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Verify HMAC
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mac_verify(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "mac_verify", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Validate an HPS image
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_hps_img_validate(struct fcs_cmd_context *ctx)
{
	struct fcs_cmd_context *ctx_ptr = ctx;
	FCS_OSAL_INT ret = 0;

	ret = put_devattr(fcs_dev_local, "hps_image_validate",
			  (FCS_OSAL_CHAR *)&ctx_ptr,
			  sizeof(struct fcs_cmd_context *));
	if (ret != 0)
		*ctx_ptr->error_code_addr =
			ret; /* Return the error code from put_devattr */
	else if (*ctx_ptr->error_code_addr)
		FCS_LOG_ERR("Failed to validate HPS image with sdm error code = %x\n",
			    *ctx_ptr->error_code_addr);

	return *ctx_ptr->error_code_addr;
}

/**
 * @brief ECDSA data sign initialization
 * 
 * @param ctx Context pointer to the context of the command
 * 
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_data_sign_init(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_sign_init",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief ECDSA data sign update stage
 * 
 * @param ctx Context pointer to the context of the command
 * 
 * @return 0 on success, otherwise value on error.
*/
static FCS_OSAL_INT
fcs_linux_ecdsa_data_sign_update(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_sign_up",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief ECDSA data sign final stage
 * 
 * @param ctx Context pointer to the context of the command
 * 
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_data_sign_final(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_sign_final",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief ECDSA data verify initialization
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_data_verify_init(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_verify_init",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief ECDSA data verify update stage
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT
fcs_linux_ecdsa_data_verify_update(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_verify_up",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief ECDSA data verify final stage
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_data_verify_final(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_data_verify_final",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform AES encryption/decryption operation init stage
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_aes_crypt_init(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "aes_crypt_init",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform AES encryption/decryption operation update stage
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_aes_crypt_update(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "aes_crypt_update",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform AES encryption/decryption operation final stage
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_aes_crypt_final(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "aes_crypt_final",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform SDOS encryption operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_sdos_encrypt(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "sdos", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform SDOS decryption operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_sdos_decrypt(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "sdos", (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get ECDSA public key
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_get_pub_key(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_get_pubkey",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Generate ECDSA hash signature
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_hash_sign(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecsda_hash_sign",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Verify ECDSA hash signature
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_hash_verify(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_hash_verify",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Generate ECDSA SHA2 data signature
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_sha2_data_sign(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_sha2_data_sign",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Verify ECDSA SHA2 data signature
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_ecdsa_sha2_data_verify(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "ecdsa_sha2data_verify",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Send a generic mailbox command
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mbox_send_cmd(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "generic_mbox",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get digest initialization
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_init(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "get_digest_init",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get digest update
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_update(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "get_digest_update",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Get digest final
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_get_digest_final(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "get_digest_final",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform MAC verification init operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mac_verify_init(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "mac_verify_init",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform MAC verification update operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mac_verify_update(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "mac_verify_update",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Perform MAC verification final operation
 *
 * @param ctx Context pointer to the context of the command
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_mac_verify_final(struct fcs_cmd_context *ctx)
{
	return put_devattr(fcs_dev_local, "mac_verify_final",
			   (FCS_OSAL_CHAR *)&ctx,
			   sizeof(struct fcs_cmd_context *));
}

/**
 * @brief Initialize log level for libkcapi
 *
 * @param loglevel
 *
 * @return 0 on success, otherwise value on error.
 */
static FCS_OSAL_INT fcs_linux_kcpai_init(FCS_OSAL_CHAR *loglevel)
{
	if (!loglevel) {
		kcapi_set_verbosity(KCAPI_LOG_WARN);
		FCS_LOG_INF("No log level provided, setting to default as log_inf");
		return -EINVAL;
	}

	if (strcmp(loglevel, "log_off") == 0)
		kcapi_set_verbosity(KCAPI_LOG_NONE);
	else if (strcmp(loglevel, "log_err") == 0)
		kcapi_set_verbosity(KCAPI_LOG_ERR);
	else if (strcmp(loglevel, "log_wrn") == 0)
		kcapi_set_verbosity(KCAPI_LOG_WARN);
	else if (strcmp(loglevel, "log_inf") == 0)
		kcapi_set_verbosity(KCAPI_LOG_VERBOSE);
	else if (strcmp(loglevel, "log_dbg") == 0)
		kcapi_set_verbosity(KCAPI_LOG_DEBUG);

	return 0;
}

/**
 * @brief Bind the OSAL API to the interface.
 *
 * @param intf Pointer to the OSAL interface.
 *
 * @return 0 on success, negative value on error.
 */
static FCS_OSAL_INT fcs_linux_api_binding(struct libfcs_osal_intf *intf)
{
	if (!intf) {
		FCS_LOG_ERR("Invalid argument: intf is NULL\n");
		return -EINVAL;
	}

	intf->open_service_session = fcs_linux_open_service_session;
	intf->close_service_session = fcs_linux_close_service_session;
	intf->random_number_ext = fcs_linux_random_number_ext;
	intf->import_service_key = fcs_linux_import_service_key;
	intf->export_service_key = fcs_linux_export_service_key;
	intf->remove_service_key = fcs_linux_remove_service_key;
	intf->get_service_key_info = fcs_linux_get_service_key_info;
	intf->create_service_key = fcs_linux_create_service_key;
	intf->get_provision_data = fcs_linux_service_get_provision_data;
	intf->counter_set = fcs_linux_counter_set;
	intf->counter_set_preauthorized = fcs_linux_counter_set_preauthorized;
	intf->hkdf_request = fcs_linux_hkdf_request;
	intf->get_digest_init = fcs_linux_get_digest_init;
	intf->get_digest_update = fcs_linux_get_digest_update;
	intf->get_digest_final = fcs_linux_get_digest_final;
	intf->get_digest = fcs_linux_get_digest;
	intf->mac_verify = fcs_linux_mac_verify;
	intf->mac_verify_init = fcs_linux_mac_verify_init;
	intf->mac_verify_update = fcs_linux_mac_verify_update;
	intf->mac_verify_final = fcs_linux_mac_verify_final;
	intf->aes_crypt = fcs_linux_aes_crypt;
	intf->ecdh_req = fcs_linux_ecdh_req;
	intf->get_chip_id = fcs_linux_get_chip_id;
	intf->attestation_get_certificate = fcs_linux_attestation_get_certificate;
	intf->attestation_cert_reload = fcs_linux_attestation_cert_reload;
	intf->mctp_cmd_send = fcs_linux_mctp_cmd_send;
	intf->get_jtag_idcode = fcs_linux_get_jtag_idcode;
	intf->get_device_identity = fcs_linux_get_device_identity;
	intf->qspi_open = fcs_linux_qspi_open;
	intf->qspi_close = fcs_linux_qspi_close;
	intf->qspi_cs = fcs_linux_qspi_set_cs;
	intf->qspi_read = fcs_linux_qspi_read;
	intf->qspi_write = fcs_linux_qspi_write;
	intf->qspi_erase = fcs_linux_qspi_erase;
	intf->sdos_encrypt = fcs_linux_sdos_encrypt;
	intf->sdos_decrypt = fcs_linux_sdos_decrypt;
	intf->ecdsa_get_pub_key = fcs_linux_ecdsa_get_pub_key;
	intf->ecdsa_hash_sign = fcs_linux_ecdsa_hash_sign;
	intf->ecdsa_hash_verify = fcs_linux_ecdsa_hash_verify;
	intf->ecdsa_sha2_data_sign = fcs_linux_ecdsa_sha2_data_sign;
	intf->ecdsa_sha2_data_verify = fcs_linux_ecdsa_sha2_data_verify;
	intf->hps_img_validate = fcs_linux_hps_img_validate;
	intf->mbox_send_cmd = fcs_linux_mbox_send_cmd;
	intf->ecdsa_data_sign_init = fcs_linux_ecdsa_data_sign_init;
	intf->ecdsa_data_sign_update = fcs_linux_ecdsa_data_sign_update;
	intf->ecdsa_data_sign_final = fcs_linux_ecdsa_data_sign_final;
	intf->ecdsa_data_verify_init = fcs_linux_ecdsa_data_verify_init;
	intf->ecdsa_data_verify_update = fcs_linux_ecdsa_data_verify_update;
	intf->ecdsa_data_verify_final = fcs_linux_ecdsa_data_verify_final;
	intf->aes_crypt_init = fcs_linux_aes_crypt_init;
	intf->aes_crypt_update = fcs_linux_aes_crypt_update;
	intf->aes_crypt_final = fcs_linux_aes_crypt_final;

	return 0;
}

/**
 * @brief Initialize the OSAL.
 *
 * @param intf Pointer to the OSAL interface.
 * @param loglevel set log level
 *
 * @return 0 on success, negative value on error.
 */

FCS_OSAL_INT libfcs_osal_init(struct libfcs_osal_intf *intf,
			      FCS_OSAL_CHAR *loglevel)
{
	FCS_OSAL_INT ret;

	/* Bind the OSAL APIs */
	ret = fcs_linux_api_binding(intf);

	if (ret != 0) {
		FCS_LOG_ERR("Error in binding OSAL APIs\n");
		return ret;
	}

	ret = fcs_linux_kcpai_init(loglevel);
	if (ret < 0) {
		FCS_LOG_ERR("Failed to initialize KCAPI: %s\n", strerror(-ret));
		return ret;
	}

	return 0;
}
