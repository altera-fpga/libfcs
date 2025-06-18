// SPDX-License-Identifier: MIT-0
/*
 * Copyright (C) 2025 Altera
 */

/**
 * @file libfcs.c
 * @brief Implementation of the FCS library functions.
 */

#include <libfcs.h>
#include <libfcs_osal.h>
#include <libfcs_logging.h>
#include <string.h>
#include <errno.h>

#define CRYPTO_HKDF_MAX_SZ 384

/**
 * @brief Enumeration for the state of the FCS library.
 */
enum fcs_state {
	un_initialized, /**< Library is not initialized */
	in_progress,    /**< Library initialization is in progress */
	initialized,    /**< Library is initialized */
};

/**
 * @brief Structure to hold the context of the FCS library.
 */
struct fcs_context {
	enum fcs_state state;	/**< Current state of the library */
	FCS_OSAL_MUTEX mutex;		/**< Mutex for thread safety */
	FCS_OSAL_MUTEX hps_img_verify_mutex;
};

/**
 * @brief Global context for the FCS library.
 */
static struct fcs_context ctx;

/**
 * @brief Global interface for the OSAL functions.
 */
static struct libfcs_osal_intf *intf;

/**
 * @brief Macro to lock the mutex.
 */
#define MUTEX_LOCK()   fcs_mutex_timedlock(&ctx.mutex, FCS_TIME_FOREVER)

/**
 * @brief Macro to unlock the mutex.
 */
#define MUTEX_UNLOCK() fcs_mutex_unlock(&ctx.mutex)

/**
 * @brief Initializes the FCS library.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT libfcs_init(FCS_OSAL_CHAR *log_level)
{
	FCS_OSAL_INT ret = 0;

	/* Check if the library is already initialized or in the process of initialization */
	if (ctx.state != un_initialized) {
		FCS_LOG_WRN("FCS library already initialized or initialization in progress\n");
		return 0;
	}

	/* Set the state to in_progress */
	ctx.state = in_progress;

	FCS_LOG_DBG("Initializing FCS library\n");

	/* Initialize logging */
	ret = fcs_logging_init(log_level);
	if (ret != 0) {
		FCS_LOG_ERR("Error in initializing logging");
		return ret;
	}

	/* Initialize the mutex */
	ret = fcs_mutex_init(&ctx.mutex);
	if (ret != 0) {
		FCS_LOG_ERR("Error in initializing mutex");
		return ret;
	}

	/* Initialize the mutex */
	ret = fcs_mutex_init(&ctx.hps_img_verify_mutex);
	if (ret != 0) {
		FCS_LOG_ERR("Error in initializing hps image verify mutex");
		return ret;
	}

	intf = fcs_malloc(sizeof(struct libfcs_osal_intf));
	if (!intf) {
		FCS_LOG_ERR("Error in allocating memory for OSAL interface\n");
		return -ENOMEM;
	}

	ret = libfcs_osal_init(intf, log_level);
	if (ret != 0) {
		FCS_LOG_ERR("Error in initializing OSAL\n");
		return ret;
	}

	/* Set the state to initialized */
	ctx.state = initialized;

	return ret;
}

/**
 * @brief Opens a service session.
 *
 * @param session_id Pointer to the session UUID.
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_open_service_session(FCS_OSAL_UUID *session_id)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context open_session_ctx;
	FCS_OSAL_UINT suuid_len = FCS_OSAL_UUID_SIZE;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!session_id) {
		FCS_LOG_ERR("Invalid argument: session_id is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->open_service_session) {
		FCS_LOG_ERR("Open service session API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs open service session\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Open service session\n");

	memset(&open_session_ctx, 0, sizeof(struct fcs_cmd_context));

	open_session_ctx.open_session.suuid = session_id;
	open_session_ctx.open_session.suuid_len = &suuid_len;
	open_session_ctx.error_code_addr = &err_code;

	ret = intf->open_service_session(&open_session_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in opening service session  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Session open failed with sdm error code:%d\n", err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs open service session\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Closes a service session.
 *
 * @param session_id Pointer to the session UUID.
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_close_service_session(FCS_OSAL_UUID *session_id)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context close_session_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!session_id) {
		FCS_LOG_ERR("Invalid argument: session_id is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->close_service_session) {
		FCS_LOG_ERR("Close service session API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs close service session\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Closing service session\n");

	memset(&close_session_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(close_session_ctx.close_session.suuid, session_id,
	       FCS_OSAL_UUID_SIZE);
	close_session_ctx.error_code_addr = &err_code;

	ret = intf->close_service_session(&close_session_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in closing service session  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Session close failed with sdm error code:%d\n", err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs close service session\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Generates a random number.
 *
 * @param rng Output buffer.
 * @param session_id Session UUID.
 * @param context_id Context ID.
 * @param rnsize Random number size.
 * @return Random number.
 */
FCS_OSAL_INT fcs_random_number_ext(FCS_OSAL_UUID *session_id,
				   FCS_OSAL_U32 context_id, FCS_OSAL_CHAR *rng,
				   FCS_OSAL_U32 rnsize)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context rnd_no_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!rng) {
		FCS_LOG_ERR("Invalid argument: rng is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->random_number_ext) {
		FCS_LOG_ERR("Random number API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs random number ext\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Generating Random Number\n");

	memset(&rnd_no_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(rnd_no_ctx.rng.suuid, session_id, FCS_OSAL_UUID_SIZE);
	rnd_no_ctx.rng.context_id = context_id;
	rnd_no_ctx.rng.rng = rng;
	rnd_no_ctx.rng.rng_len = rnsize;
	rnd_no_ctx.error_code_addr = &err_code;

	ret = intf->random_number_ext(&rnd_no_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in generating random number\n");
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to generate the random number with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs random number ext\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * Imports a service key identified by the given session ID.
 *
 * @param session_uuid The service ID of the key to import
 * @param key The source of the key to import
 * @param keylen length of key object to import
 * @param status return status of key import
 * @param imp_resp_len response status length
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_import_service_key(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_CHAR *key, FCS_OSAL_INT keylen,
				    FCS_OSAL_CHAR *status,
				    FCS_OSAL_UINT *imp_resp_len)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context import_srvc_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!key) {
		FCS_LOG_ERR("Invalid argument: ket is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->import_service_key) {
		FCS_LOG_ERR("Import service key API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs import service key\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Importing service key\n");

	memset(&import_srvc_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(import_srvc_ctx.import_key.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);
	import_srvc_ctx.import_key.key = key;
	import_srvc_ctx.import_key.key_len = keylen;
	import_srvc_ctx.import_key.status = status;
	import_srvc_ctx.import_key.status_len = imp_resp_len;
	import_srvc_ctx.error_code_addr = &err_code;

	ret = intf->import_service_key(&import_srvc_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in importing service key  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to import service key with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs import service key\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * Exports a service key identified by the given session ID.
 *
 * @param session_uuid The session ID
 * @param keyid imported key's key ID
 * @param key The destination buffer address of the key to export.
 * @param keylen length of exported key
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_export_service_key(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_U32 keyid, FCS_OSAL_CHAR *key,
				    FCS_OSAL_UINT *keylen)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context export_srvc_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!key || !keylen) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->export_service_key) {
		FCS_LOG_ERR("Export service key API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs export service key\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Exporting service key\n");

	memset(&export_srvc_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(export_srvc_ctx.export_key.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);
	export_srvc_ctx.export_key.key_id = keyid;
	export_srvc_ctx.export_key.key = key;
	export_srvc_ctx.export_key.key_len = keylen;
	export_srvc_ctx.error_code_addr = &err_code;

	ret = intf->export_service_key(&export_srvc_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in exporting service key  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to export service key with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs export service key\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Removes a service key identified by the given session ID.
 *
 * @param session_uuid The session ID of the key to remove.
 * @param keyid The key ID
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_remove_service_key(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_U32 keyid)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context rm_srvc_key_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->remove_service_key) {
		FCS_LOG_ERR("Remove service key API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs remove service key\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Removing service key\n");

	memset(&rm_srvc_key_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(rm_srvc_key_ctx.remove_key.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);
	rm_srvc_key_ctx.remove_key.key_id = keyid;
	rm_srvc_key_ctx.error_code_addr = &err_code;

	ret = intf->remove_service_key(&rm_srvc_key_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in removing service key  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to remove service key with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs remove service key\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Get the service key information.
 *
 * @param session_uuid
 * @param keyid The key ID
 * @param keyinfo The key information.
 * @param keyinfolen The length of the key information.
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_get_service_key_info(FCS_OSAL_UUID *session_uuid,
				      FCS_OSAL_U32 keyid,
				      FCS_OSAL_CHAR *keyinfo,
				      FCS_OSAL_UINT *keyinfolen)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context key_info_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!keyinfo || !keyinfolen) {
		FCS_LOG_ERR("Invalid argument: keyinfo is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_service_key_info) {
		FCS_LOG_ERR("Get service key info API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs get service key info\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Getting service key info\n");

	memset(&key_info_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(key_info_ctx.key_info.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	key_info_ctx.key_info.key_id = keyid;
	key_info_ctx.key_info.info = keyinfo;
	key_info_ctx.key_info.info_len = keyinfolen;
	key_info_ctx.error_code_addr = &err_code;

	ret = intf->get_service_key_info(&key_info_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting service key info  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get service key info with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs get service key info\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Create a service key.
 *
 * @param session_uuid The session UUID.
 * @param key The key object.
 * @param keylen The length of the key.
 * @param status The status of the create key.
 * @param status_len status length
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_create_service_key(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_CHAR *key, FCS_OSAL_INT keylen,
				    FCS_OSAL_CHAR *status,
				    FCS_OSAL_UINT status_len)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context create_key_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!key || !status) {
		FCS_LOG_ERR("Invalid argument: key or status is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->create_service_key) {
		FCS_LOG_ERR("Create service key API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs create service key\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Creating service key\n");

	memset(&create_key_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(create_key_ctx.create_key.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);
	create_key_ctx.create_key.key = key;
	create_key_ctx.create_key.key_len = keylen;
	create_key_ctx.create_key.status = status;
	create_key_ctx.create_key.status_len = &status_len;
	create_key_ctx.error_code_addr = &err_code;

	ret = intf->create_service_key(&create_key_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in creating service key  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to create service key with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs create service key\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Retrieves the provision data.
 *
 * This function retrieves the provision data for the FCS service and stores
 * it in the provided buffer.
 *
 * @param buff Pointer to the buffer where the provision data will be stored.
 * @param pd_size Pointer to the size of the buffer in bytes.
 *
 * @return The number of bytes written to the buffer, or a negative error code
 * if an error occurred.
 */
FCS_OSAL_INT fcs_service_get_provision_data(FCS_OSAL_CHAR *buff,
					    FCS_OSAL_U32 *pd_size)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context prov_data_ctx;
	FCS_OSAL_INT err_code = 0;

	/* Check for invalid argument */
	if (!buff) {
		FCS_LOG_ERR("Invalid argument: buff is NULL\n");
		return -EINVAL;
	}

	if (!pd_size) {
		FCS_LOG_ERR("Invalid argument: pd_size is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_provision_data) {
		FCS_LOG_ERR("Service get provision data API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs service get provision_data\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Retrieving provision data\n");

	memset(&prov_data_ctx, 0, sizeof(struct fcs_cmd_context));

	prov_data_ctx.prov_data.data = buff;
	prov_data_ctx.prov_data.data_len = pd_size;
	prov_data_ctx.error_code_addr = &err_code;

	ret = intf->get_provision_data(&prov_data_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting provision data  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get provision data with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs service get provision_data\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief This API requests SDM to set one specific counter to specified
 * value in the CMF or to cancel an existing key.
 *
 * @param buffer containing the signed counter set request.
 * @param size input buffer size.
 * @param test indicates the cache ram should be used instead of fuses.
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_service_counter_set(FCS_OSAL_CHAR *buffer, FCS_OSAL_INT size,
				     FCS_OSAL_INT test,
				     FCS_OSAL_CHAR *cert_status)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ctr_set_ctx;
	FCS_OSAL_INT err_code = 0;
	FCS_OSAL_UINT cert_status_len = sizeof(cert_status);

	if (!buffer) {
		FCS_LOG_ERR("Invalid argument: buffer is NULL\n");
		return -EINVAL;
	}

	if (size <= 0) {
		FCS_LOG_ERR("Invalid argument: size must be greater than 0\n");
		return -EINVAL;
	}

	if (test != 0 && test != 1) {
		FCS_LOG_ERR("Invalid argument: test must be 0 or 1\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->counter_set) {
		FCS_LOG_ERR("Service counter set API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs service counter set command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Setting service counter");

	memset(&ctr_set_ctx, 0, sizeof(struct fcs_cmd_context));

	ctr_set_ctx.ctr_set.cache = (test << 31);
	ctr_set_ctx.ctr_set.ccert = buffer;
	ctr_set_ctx.ctr_set.ccert_len = size;
	ctr_set_ctx.ctr_set.status = cert_status;
	ctr_set_ctx.ctr_set.status_len = &cert_status_len;
	ctr_set_ctx.error_code_addr = &err_code;

	ret = intf->counter_set(&ctr_set_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in setting service counter  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to set service counter with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs service counter_set command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Sets counter value w/o signed certificate
 *
 * This function sets the preauthorized service counter based on the specified
 * type and value.
 *
 * @param type The type of the service counter.
 * @param value The value to set for the service counter.
 * @param test An integer parameter for testing purposes.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_service_counter_set_preauthorized(FCS_OSAL_U8 type,
						   FCS_OSAL_U32 value,
						   FCS_OSAL_INT test)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ctr_set_ctx;
	FCS_OSAL_INT err_code = 0;

	if (type == 0) {
		FCS_LOG_ERR("Invalid argument: type is 0\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->counter_set_preauthorized) {
		FCS_LOG_ERR("Service counter set preauthorized API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in counter set preauthorized command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Setting preauthorized service counter\n");

	memset(&ctr_set_ctx, 0, sizeof(struct fcs_cmd_context));

	ctr_set_ctx.ctr_set_preauth.ctr_type = type;
	ctr_set_ctx.ctr_set_preauth.ctr_val = value;
	ctr_set_ctx.ctr_set_preauth.test = (test << 31);
	ctr_set_ctx.error_code_addr = &err_code;

	ret = intf->counter_set_preauthorized(&ctr_set_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in setting preauthorized service counter  %s\n",
			    strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to set preauth service counter with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in counter set preauth command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Get the digest of the input data.
 *
 * This function gets the digest of the input data using the specified
 * session UUID, context ID, key ID, source buffer, source buffer size,
 * destination buffer, and destination buffer size.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param keyid Key ID.
 * @param req Get digest request structure
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_get_digest(FCS_OSAL_UUID *session_uuid,
			    FCS_OSAL_U32 context_id, FCS_OSAL_U32 keyid,
			    struct fcs_digest_get_req *req)
{
	FCS_OSAL_INT err_code = 0;
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context digest_ctx;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (!req->digest) {
		FCS_LOG_ERR("Invalid argument: digest is NULL\n");
		return -EINVAL;
	}

	if (!req->digest_len) {
		FCS_LOG_ERR("Invalid argument: digest_len is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_digest) {
		FCS_LOG_ERR("Get digest API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs get digest\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Getting digest\n");

	memset(&digest_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(digest_ctx.dgst.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	digest_ctx.dgst.context_id = context_id;
	digest_ctx.dgst.key_id = keyid;
	digest_ctx.dgst.sha_op_mode = req->sha_op_mode;
	digest_ctx.dgst.sha_digest_sz = req->sha_digest_sz;
	digest_ctx.dgst.src = req->src;
	digest_ctx.dgst.src_len = req->src_len;
	digest_ctx.dgst.digest = req->digest;
	digest_ctx.dgst.digest_len = req->digest_len;
	digest_ctx.dgst.stage = 0;
	digest_ctx.error_code_addr = &err_code;

	ret = intf->get_digest(&digest_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting digest\n");
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get digest with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs get digest\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Verifies the MAC.
 *
 * This function verifies the MAC for the specified session UUID, context ID,
 * key ID, operation mode, digest size, source buffer, source buffer size,
 * destination buffer, destination buffer size, and user data size.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param keyid Key ID.
 * @param req Mac verify request
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_mac_verify(FCS_OSAL_UUID *session_uuid,
			    FCS_OSAL_U32 context_id, FCS_OSAL_U32 keyid,
			    struct fcs_mac_verify_req *req)
{
	FCS_OSAL_INT err_code = 0;
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context mac_ctx;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (!req->dst_sz) {
		FCS_LOG_ERR("Invalid argument: dst_sz is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->mac_verify) {
		FCS_LOG_ERR("MAC verify API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs mac verify\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Verifying MAC\n");

	memset(&mac_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(mac_ctx.mac_verify.suuid, session_uuid, FCS_OSAL_UUID_SIZE);

	mac_ctx.mac_verify.context_id = context_id;
	mac_ctx.mac_verify.key_id = keyid;
	mac_ctx.mac_verify.sha_op_mode = req->op_mode;
	mac_ctx.mac_verify.sha_digest_sz = req->dig_sz;
	mac_ctx.mac_verify.src = req->src;
	mac_ctx.mac_verify.src_size = req->src_sz;
	mac_ctx.mac_verify.dst = req->dst;
	mac_ctx.mac_verify.dst_size = req->dst_sz;
	mac_ctx.mac_verify.user_data_size = req->user_data_sz;
	mac_ctx.error_code_addr = &err_code;

	ret = intf->mac_verify(&mac_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in verifying MAC  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to verify MAC with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs mac verify\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Encrypts data using SDOS.
 *
 * This function encrypts the input data using the specified session UUID,
 * context ID, operation mode, source buffer, source buffer size,
 * destination buffer, and destination buffer size.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param req encryption request structure
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_sdos_encrypt(FCS_OSAL_UUID *session_uuid,
			      FCS_OSAL_U32 context_id,
			      struct fcs_sdos_enc_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context sdos_ctx;
	FCS_OSAL_INT err_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (!req->dst_sz) {
		FCS_LOG_ERR("Invalid argument: dst_sz is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->sdos_encrypt) {
		FCS_LOG_ERR("SDOS encrypt API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs sdos encrypt\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Encrypting data\n");

	memset(&sdos_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(sdos_ctx.sdos.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	sdos_ctx.sdos.context_id = context_id;
	sdos_ctx.sdos.op_mode = req->op_mode;
	sdos_ctx.sdos.src = req->src;
	sdos_ctx.sdos.src_size = req->src_sz;
	sdos_ctx.sdos.dst = req->dst;
	sdos_ctx.sdos.dst_size = req->dst_sz;
	sdos_ctx.sdos.id = req->id;
	sdos_ctx.sdos.own = req->own;
	sdos_ctx.sdos.pad = 0;
	sdos_ctx.error_code_addr = &err_code;

	ret = intf->sdos_encrypt(&sdos_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in encrypting data  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to perform SDOS encryption with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs sdos encrypt\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Decrypts the given source data using the specified session UUID and
 * context ID.
 *
 * This function performs decryption on the provided source data (`src`) and
 * stores the result in the destination buffer (`dst`).
 * The decryption process is determined by the operation mode (`op_mode`) and
 * may involve padding as specified by the `pad` parameter.
 *
 * @param session_uuid A pointer to the session UUID used for decryption.
 * @param context_id The context ID associated with the decryption operation.
 * @param req SDOS decryption request structure
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_sdos_decrypt(FCS_OSAL_UUID *session_uuid,
			      FCS_OSAL_U32 context_id,
			      struct fcs_sdos_dec_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context sdos_ctx;
	FCS_OSAL_INT err_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (!req->dst_sz) {
		FCS_LOG_ERR("Invalid argument: dst_sz is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->sdos_decrypt) {
		FCS_LOG_ERR("SDOS decrypt API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs sdos decrypt\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Decrypting data\n");

	memset(&sdos_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(sdos_ctx.sdos.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	sdos_ctx.sdos.context_id = context_id;
	sdos_ctx.sdos.op_mode = req->op_mode;
	sdos_ctx.sdos.src = req->src;
	sdos_ctx.sdos.src_size = req->src_sz;
	sdos_ctx.sdos.pad = req->pad;
	sdos_ctx.sdos.dst = req->dst;
	sdos_ctx.sdos.dst_size = req->dst_sz;
	sdos_ctx.error_code_addr = &err_code;

	ret = intf->sdos_decrypt(&sdos_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in decrypting data  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to perform SDOS decrypting with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs sdos decrypt\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Request HKDF operation.
 *
 * This function requests the HKDF operation for the specified session UUID,
 * key ID, step type, MAC mode, IKM, and IKM length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param req hkdf request structure
 *
 * @return 0 on success, negative value on error.
 */

FCS_OSAL_INT fcs_hkdf_request(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 key_id,
			      struct fcs_hkdf_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context hkdf_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!req) {
		FCS_LOG_ERR("Invalid argument: HKDF request is not valid\n");
		return -EINVAL;
	}

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->input1_len != 0) {
		if (!req->input1) {
			FCS_LOG_ERR("Invalid argument: ikm is NULL\n");
			return -EINVAL;
		}
	}

	if (req->output_key_obj_len != 0) {
		if (!req->output_key_obj) {
			FCS_LOG_ERR("Invalid argument: output_key_obj is NULL\n");
			return -EINVAL;
		}
	}

	if (!req->hkdf_resp) {
		FCS_LOG_ERR("Invalid argument: hkdf resp is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->hkdf_request) {
		FCS_LOG_ERR("HKDF request API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs hkdf request command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting HKDF operation\n");

	memset(&hkdf_ctx, 0, sizeof(struct fcs_cmd_context));

	memcpy(hkdf_ctx.hkdf_req.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	hkdf_ctx.hkdf_req.key_id = key_id;
	hkdf_ctx.hkdf_req.step_type = req->step_type;
	hkdf_ctx.hkdf_req.mac_mode = req->mac_mode;
	hkdf_ctx.hkdf_req.ikm = req->input1;
	hkdf_ctx.hkdf_req.ikm_len = req->input1_len;
	hkdf_ctx.hkdf_req.info = req->input2;
	hkdf_ctx.hkdf_req.info_len = req->input2_len;
	hkdf_ctx.hkdf_req.output_key_obj = req->output_key_obj;
	hkdf_ctx.hkdf_req.output_key_obj_len = req->output_key_obj_len;
	hkdf_ctx.hkdf_req.hkdf_resp = req->hkdf_resp;
	hkdf_ctx.error_code_addr = &error_code;

	ret = intf->hkdf_request(&hkdf_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting HKDF operation  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to perform HKDF operation with sdm error code = %x\n",
			    error_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs hkdf request command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Request AES encryption/decryption operation.
 *
 * This function requests the AES encryption/decryption operation
 * for the specified session UUID, key ID, context ID, crypt mode,
 * block mode, IV, IV length, input data, input length, output data,
 * output length, status, and status length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req AES request structure.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_aes_crypt(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 key_id,
			   FCS_OSAL_U32 context_id, struct fcs_aes_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context aes_ctx;
	FCS_OSAL_INT error_code = 0;

	FCS_LOG_DBG("AES crypt request\n");

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->crypt_mode != FCS_AES_ENCRYPT &&
	    req->crypt_mode != FCS_AES_DECRYPT) {
		FCS_LOG_ERR("Invalid argument: crypt_mode\n");
		return -EINVAL;
	}

	if (req->block_mode != FCS_AES_BLOCK_MODE_ECB &&
	    req->block_mode != FCS_AES_BLOCK_MODE_CBC &&
	    req->block_mode != FCS_AES_BLOCK_MODE_CTR &&
	    req->block_mode != FCS_AES_BLOCK_MODE_GCM &&
	    req->block_mode != FCS_AES_BLOCK_MODE_GHASH) {
		FCS_LOG_ERR("Invalid argument: block_mode\n");
		return -EINVAL;
	}

	if (req->block_mode != FCS_AES_BLOCK_MODE_ECB && !req->iv) {
		FCS_LOG_ERR("Invalid argument: iv is NULL\n");
		return -EINVAL;
	}

	if (req->block_mode != FCS_AES_BLOCK_MODE_ECB &&
	    req->iv_len != FCS_AES_CRYPT_BLOCK_SIZE) {
		FCS_LOG_ERR("Invalid argument: iv_len must be greater than 0\n");
		return -EINVAL;
	}

	if (req->iv_source != FCS_AES_IV_SOURCE_INTERNAL &&
	    req->iv_source != FCS_AES_IV_SOURCE_EXTERNAL) {
		FCS_LOG_ERR("Invalid argument: iv_source\n");
		return -EINVAL;
	}

	if (req->block_mode == FCS_AES_BLOCK_MODE_GCM ||
	    req->block_mode == FCS_AES_BLOCK_MODE_GHASH) {
		if (req->tag_len != FCS_AES_GCM_TAG_SIZE) {
			FCS_LOG_ERR("Invalid argument: tag_len\n");
			return -EINVAL;
		}

		if (req->aad_len > FCS_AES_GCM_MAX_AAD_SIZE) {
			FCS_LOG_ERR("Invalid argument: aad_len must be greater than 0\n");
			return -EINVAL;
		}

		if (!req->aad) {
			FCS_LOG_ERR("Invalid argument: aad is NULL\n");
			return -EINVAL;
		}
	}

	if (!req->input) {
		FCS_LOG_ERR("Invalid argument: input is NULL\n");
		return -EINVAL;
	}

	if (req->ip_len <= 0) {
		FCS_LOG_ERR("Invalid argument: ip_len must be greater than 0\n");
		return -EINVAL;
	}

	if (!req->output) {
		FCS_LOG_ERR("Invalid argument: output is NULL\n");
		return -EINVAL;
	}

	if (!req->op_len) {
		FCS_LOG_ERR("Invalid argument: op_len is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->aes_crypt) {
		FCS_LOG_ERR("AES crypt API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs aes crypt command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting AES encryption/decryption operation\n");

	memcpy(aes_ctx.aes.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	aes_ctx.aes.kid = key_id;
	aes_ctx.aes.cid = context_id;
	aes_ctx.aes.mode = req->block_mode;
	aes_ctx.aes.crypt = req->crypt_mode;
	aes_ctx.aes.iv_source = req->iv_source;
	aes_ctx.aes.tag = req->tag;
	aes_ctx.aes.tag_len = req->tag_len;
	aes_ctx.aes.aad_len = req->aad_len;
	aes_ctx.aes.aad = req->aad;
	aes_ctx.aes.iv = req->iv;
	aes_ctx.aes.input = req->input;
	aes_ctx.aes.ip_len = req->ip_len;
	aes_ctx.aes.output = req->output;
	aes_ctx.aes.op_len = req->op_len;
	aes_ctx.error_code_addr = &error_code;

	ret = intf->aes_crypt(&aes_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting AES encryption/decryption operation  %s\n",
			    strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to perform AES encryption/decryption operation with sdm error code = %x\n",
			    error_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs aes crypt command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Generates shared secret.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req ECDH request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_ecdh_request(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 key_id,
			  FCS_OSAL_U32 context_id, struct fcs_ecdh_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdh_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!req->pubkey) {
		FCS_LOG_ERR("Invalid argument: pubkey is NULL\n");
		return -EINVAL;
	}

	if (!req->shared_secret) {
		FCS_LOG_ERR("Invalid argument: shared_secret is NULL\n");
		return -EINVAL;
	}

	if (!req->shared_secret_len) {
		FCS_LOG_ERR("Invalid argument: shared secret len is NULL\n");
		return -EINVAL;
	}

	if ((req->ecc_curve == FCS_ECC_CURVE_NIST_P256 &&
	     req->pubkey_len != FCS_ECDH_P256_PUBKEY_LEN &&
	     *req->shared_secret_len == FCS_ECDH_P256_SECRET_LEN) ||
	    (req->ecc_curve == FCS_ECC_CURVE_NIST_P384 &&
	     req->pubkey_len != FCS_ECDH_P384_PUBKEY_LEN &&
	     *req->shared_secret_len == FCS_ECDH_P384_SECRET_LEN) ||
	    (req->ecc_curve == FCS_ECC_CURVE_BRAINPOOL_P256 &&
	     req->pubkey_len != FCS_ECDH_BP256_PUBKEY_LEN &&
	     *req->shared_secret_len == FCS_ECDH_BP256_SECRET_LEN) ||
	    (req->ecc_curve == FCS_ECC_CURVE_BRAINPOOL_P384 &&
	     req->pubkey_len != FCS_ECDH_BP384_PUBKEY_LEN &&
	     *req->shared_secret_len == FCS_ECDH_BP384_SECRET_LEN)) {
		FCS_LOG_ERR("Invalid argument: pubkey length or shared secret length\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdh_req) {
		FCS_LOG_ERR("ECDH request API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs ecdh req command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDH operation\n");

	memcpy(ecdh_ctx.ecdh_req.suuid, session_uuid, FCS_OSAL_UUID_SIZE);
	ecdh_ctx.ecdh_req.kid = key_id;
	ecdh_ctx.ecdh_req.cid = context_id;
	ecdh_ctx.ecdh_req.ecc_curve = req->ecc_curve;
	ecdh_ctx.ecdh_req.pubkey = req->pubkey;
	ecdh_ctx.ecdh_req.pubkey_len = req->pubkey_len;
	ecdh_ctx.ecdh_req.sh_secret = req->shared_secret;
	ecdh_ctx.ecdh_req.sh_secret_len = req->shared_secret_len;
	ecdh_ctx.error_code_addr = &error_code;

	ret = intf->ecdh_req(&ecdh_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDH operation  %s\n",
			    strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to perform ECDH operation with sdm error code = %x\n",
			    error_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs ecdh req command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Get the chip ID.
 *
 * This function retrieves the chip ID and stores it in the provided buffer.
 *
 * @param chip_id_lo Pointer to the lower 32 bits of the chip ID.
 * @param chip_id_hi Pointer to the higher 32 bits of the chip ID.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_get_chip_id(FCS_OSAL_U32 *chip_id_lo, FCS_OSAL_U32 *chip_id_hi)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context chipid_ctx;

	if (!chip_id_lo || !chip_id_hi) {
		FCS_LOG_ERR("Invalid argument: pointer to chip ID is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_chip_id) {
		FCS_LOG_ERR("Get chip ID API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs get chip id command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Getting chip ID\n");

	memset(&chipid_ctx, 0, sizeof(struct fcs_cmd_context));

	chipid_ctx.chip_id.chip_id_lo = chip_id_lo;
	chipid_ctx.chip_id.chip_id_hi = chip_id_hi;
	chipid_ctx.error_code_addr = &err_code;

	ret = intf->get_chip_id(&chipid_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting chip ID  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get chip ID with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs get chip id command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Request to get the certificate.
 *
 * This function requests the certificate for the specified certificate request.
 *
 * @param cert_request The desired certificate request.
 * @param cert Pointer to the certificate.
 * @param cert_size Pointer to the certificate size.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_attestation_get_certificate(FCS_OSAL_INT cert_request,
					     FCS_OSAL_CHAR *cert,
					     FCS_OSAL_U32 *cert_size)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context attestation_ctx;

	if (!cert) {
		FCS_LOG_ERR("Invalid argument: cert is NULL\n");
		return -EINVAL;
	}

	if (!cert_size) {
		FCS_LOG_ERR("Invalid argument: cert_size is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->attestation_get_certificate) {
		FCS_LOG_ERR("Attestation get certificate API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs attestation get certificate\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting to get the certificate\n");

	memset(&attestation_ctx, 0, sizeof(struct fcs_cmd_context));

	attestation_ctx.attestation_cert.cert_request = cert_request;
	attestation_ctx.attestation_cert.cert = cert;
	attestation_ctx.attestation_cert.cert_size = cert_size;
	attestation_ctx.error_code_addr = &err_code;

	ret = intf->attestation_get_certificate(&attestation_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting to get the attestation certificate  %s\n",
			    strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get attestation certificate with sdm error code = %x\n",
			    err_code);
	}

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs attestation get certificate\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Reloads the attestation certificate.
 *
 * This function reloads the attestation certificate for the specified
 * certificate request.
 *
 * @param cert_request The desired certificate request.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_attestation_certificate_reload(FCS_OSAL_INT cert_request)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context attestation_rld_ctx;

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->attestation_cert_reload) {
		FCS_LOG_ERR("Attestation certificate reload API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in attestation cert reload command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Reloading the certificate\n");

	memset(&attestation_rld_ctx, 0, sizeof(struct fcs_cmd_context));

	attestation_rld_ctx.attestation_cert_reload.cert_request = cert_request;
	attestation_rld_ctx.error_code_addr = &err_code;

	ret = intf->attestation_cert_reload(&attestation_rld_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in reloading the certificate  %s\n",
			    strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to reloading the attestation certificate with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in attestation certificate reload command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Sends a MCTP request
 *
 * This function sends mctp request and
 *
 * @param src Pointer to the source buffer.
 * @param src_len The source buffer length.
 * @param dst Pointer to the destination buffer.
 * @param dst_len Pointer to the destination buffer length.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_mctp_cmd_send(FCS_OSAL_CHAR *src, FCS_OSAL_U32 src_len,
			       FCS_OSAL_CHAR *dst, FCS_OSAL_U32 *dst_len)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;

	struct fcs_cmd_context mctp_ctx;

	if (!src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (!dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->mctp_cmd_send) {
		FCS_LOG_ERR("MCTP command send API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs mctp cmd send command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Sending MCTP request\n");

	memset(&mctp_ctx, 0, sizeof(struct fcs_cmd_context));

	mctp_ctx.mctp.mctp_req = src;
	mctp_ctx.mctp.mctp_req_len = src_len;
	mctp_ctx.mctp.mctp_resp = dst;
	mctp_ctx.mctp.mctp_resp_len = dst_len;
	mctp_ctx.error_code_addr = &err_code;

	ret = intf->mctp_cmd_send(&mctp_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in sending MCTP request  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to send MCTP request with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs mctp cmd send command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Get the JTAG IDCODE.
 *
 * This function retrieves the JTAG IDCODE and stores it in the provided buffer.
 *
 * @param jtag_idcode Pointer to the buffer where the JTAG IDCODE will be stored.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_get_jtag_idcode(FCS_OSAL_U32 *jtag_idcode)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context jtag_idcode_ctx;

	if (!jtag_idcode) {
		FCS_LOG_ERR("Invalid argument: jtag idcode is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_jtag_idcode) {
		FCS_LOG_ERR("Get JTAG ID code API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs get jtag idcode command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Getting JTAG ID code\n");

	memset(&jtag_idcode_ctx, 0, sizeof(struct fcs_cmd_context));

	jtag_idcode_ctx.jtag_id.jtag_idcode = jtag_idcode;
	jtag_idcode_ctx.error_code_addr = &err_code;

	ret = intf->get_jtag_idcode(&jtag_idcode_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting JTAG ID code  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get JTAG ID code with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs get jtag idcode command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Get the device identity.
 *
 * This function retrieves the device identity and stores it in the provided
 * buffer.
 *
 * @param dev_identity Pointer to the buffer where the device identity will be
 * stored.
 * @param dev_identity_length Pointer to the device identity length.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_get_device_identity(FCS_OSAL_CHAR *dev_identity,
				     FCS_OSAL_U32 *dev_identity_length)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context dev_identity_ctx;

	if (!dev_identity) {
		FCS_LOG_ERR("Invalid argument: dev_identity is NULL\n");
		return -EINVAL;
	}

	if (!dev_identity_length) {
		FCS_LOG_ERR("Invalid argument: dev_identity_length is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->get_device_identity) {
		FCS_LOG_ERR("Get device identity API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs get device identity command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Getting device identity\n");

	memset(&dev_identity_ctx, 0, sizeof(struct fcs_cmd_context));

	dev_identity_ctx.device_identity.identity = dev_identity;
	dev_identity_ctx.device_identity.identity_len = dev_identity_length;
	dev_identity_ctx.error_code_addr = &err_code;

	ret = intf->get_device_identity(&dev_identity_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in getting device identity  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to get device identity with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs get device identity command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Requests exclusive access to the QSPI interface
 *
 * This function requests exclusive access to the QSPI interface.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_open(FCS_OSAL_VOID)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->qspi_open) {
		FCS_LOG_ERR("QSPI open API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi open command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Opening QSPI\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));
	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_open(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in opening QSPI  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to open QSPI with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi open command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Closes the exculsive access to the QSPI interface
 *
 * This function closes the QSPI interface.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_close(FCS_OSAL_VOID)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->qspi_close) {
		FCS_LOG_ERR("QSPI close API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi close command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Closing QSPI\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));

	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_close(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in closing QSPI  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to close QSPI with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi close command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief configures the chip select lines for the QSPI interface
 *
 * This function selects the chip select lines
 *
 * @param chipsel The chip select value.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_set_cs(FCS_OSAL_U32 sel)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->qspi_cs) {
		FCS_LOG_ERR("QSPI CS API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi cs command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Selecting CS\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));

	qspi_ctx.qspi_cs.chipsel = sel;
	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_cs(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in selecting QSPI CS  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to select QSPI CS with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi cs command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Reads data from the QSPI interface
 *
 * This function reads data from QSPI
 *
 * @param qspi_addr The QSPI address.
 * @param buffer The buffer to store the data.
 * @param len The length of the data to read.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_read(FCS_OSAL_U32 qspi_addr, FCS_OSAL_CHAR *buffer,
			   FCS_OSAL_U32 len)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (!buffer) {
		FCS_LOG_ERR("Invalid argument: buffer is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (len > 1024 || len == 0) {
		FCS_LOG_ERR("Invalid argument: 0 < len(%u) < 1K\n", len);
		return -EINVAL;
	}

	if (!intf->qspi_read) {
		FCS_LOG_ERR("QSPI read API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi read command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Reading from QSPI\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));

	qspi_ctx.qspi_read.qspi_addr = qspi_addr;
	qspi_ctx.qspi_read.len = len;
	qspi_ctx.qspi_read.buffer = buffer;
	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_read(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in reading from QSPI  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to read from QSPI with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi read command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Writes data to the QSPI interface
 *
 * This function writes data to QSPI
 *
 * @param qspi_addr The QSPI address.
 * @param buffer The buffer to store the data.
 * @param len The length of the data to write in words.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_write(FCS_OSAL_U32 qspi_addr, FCS_OSAL_CHAR *buffer,
			    FCS_OSAL_U32 len)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (!buffer) {
		FCS_LOG_ERR("Invalid argument: buffer is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->qspi_write) {
		FCS_LOG_ERR("QSPI write API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi write command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Writing to QSPI\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));

	qspi_ctx.qspi_write.qspi_addr = qspi_addr;
	qspi_ctx.qspi_write.len = len;
	qspi_ctx.qspi_write.buffer = buffer;
	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_write(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in writing to QSPI  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to write to QSPI with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi write command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Erases data from the QSPI interface
 *
 * This function erases data from QSPI
 *
 * @param qspi_addr The QSPI address, must be 4KB aligned
 * @param size in bytes to erase, must be multiple of 4K.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_erase(FCS_OSAL_U32 qspi_addr, FCS_OSAL_U32 size)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_INT err_code = 0;
	struct fcs_cmd_context qspi_ctx;

	if (size == 0) {
		FCS_LOG_ERR("Invalid argument: size is 0\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (qspi_addr % 0x1000 != 0) {
		FCS_LOG_ERR("Invalid argument: qspi_addr is not 4KB aligned\n");
		return -EINVAL;
	}

	if (size % 0x400 != 0) {
		FCS_LOG_ERR("Invalid argument: size is not a multiple of 400\n");
		return -EINVAL;
	}

	if (!intf->qspi_erase) {
		FCS_LOG_ERR("QSPI erase API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs qspi erase command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Erasing QSPI\n");

	memset(&qspi_ctx, 0, sizeof(struct fcs_cmd_context));

	qspi_ctx.qspi_erase.qspi_addr = qspi_addr;
	qspi_ctx.qspi_erase.len = size;
	qspi_ctx.error_code_addr = &err_code;

	ret = intf->qspi_erase(&qspi_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in erasing QSPI  %s\n", strerror(errno));
	} else if (err_code) {
		ret = err_code;
		FCS_LOG_ERR("Failed to erase QSPI with sdm error code = %x\n",
			    err_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs qspi erase command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Generates a public key for the specified session UUID, context ID,
 * key ID, and ECC curve.
 *
 * This function generates a public key for the specified session UUID,
 * context ID, key ID, and ECC curve.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param ecc_curve ECC curve.
 * @param pubkey Pointer to the public key.
 * @param pubkey_len Pointer to the public key length.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_ecdsa_get_pub_key(FCS_OSAL_UUID *session_uuid,
				   FCS_OSAL_U32 context_id, FCS_OSAL_U32 key_id,
				   FCS_OSAL_U32 ecc_curve,
				   FCS_OSAL_CHAR *pubkey,
				   FCS_OSAL_U32 *pubkey_len)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdsa_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!pubkey) {
		FCS_LOG_ERR("Invalid argument: pubkey is NULL\n");
		return -EINVAL;
	}

	if (!pubkey_len) {
		FCS_LOG_ERR("Invalid argument: pubkey_len is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdsa_get_pub_key) {
		FCS_LOG_ERR("ECDSA get public key API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs ecdsa get pub key command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDSA public key\n");

	memcpy(ecdsa_ctx.ecdsa_pub_key.suuid, session_uuid, FCS_OSAL_UUID_SIZE);

	ecdsa_ctx.ecdsa_pub_key.key_id = key_id;
	ecdsa_ctx.ecdsa_pub_key.context_id = context_id;
	ecdsa_ctx.ecdsa_pub_key.ecc_curve = ecc_curve;
	ecdsa_ctx.ecdsa_pub_key.pubkey = pubkey;
	ecdsa_ctx.ecdsa_pub_key.pubkey_len = pubkey_len;
	ecdsa_ctx.error_code_addr = &error_code;

	ret = intf->ecdsa_get_pub_key(&ecdsa_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDSA public key  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to request ECDSA public key with sdm error code = %x\n",
			    error_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs ecdsa get pub key command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Signs the hash using the specified session UUID, context ID, key ID,
 * ECC curve, source buffer, source buffer length, destination buffer
 * and destination buffer length.
 *
 * This function signs the hash using the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer,
 * and destination buffer length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param req request structure pointer
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_ecdsa_hash_sign(FCS_OSAL_UUID *session_uuid,
				 FCS_OSAL_U32 context_id, FCS_OSAL_U32 key_id,
				 struct fcs_ecdsa_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdsa_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (req->src_len == 0) {
		FCS_LOG_ERR("Invalid argument: src_len is 0\n");
		return -EINVAL;
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (req->dst_len == 0) {
		FCS_LOG_ERR("Invalid argument: dst_len is zero\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdsa_hash_sign) {
		FCS_LOG_ERR("ECDSA hash sign API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs ecdsa hash sign command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDSA hash sign\n");

	memcpy(ecdsa_ctx.ecdsa_hash_sign.suuid, session_uuid, FCS_OSAL_UUID_SIZE);

	ecdsa_ctx.ecdsa_hash_sign.key_id = key_id;
	ecdsa_ctx.ecdsa_hash_sign.context_id = context_id;
	ecdsa_ctx.ecdsa_hash_sign.ecc_curve = req->ecc_curve;
	ecdsa_ctx.ecdsa_hash_sign.src = req->src;
	ecdsa_ctx.ecdsa_hash_sign.src_len = req->src_len;
	ecdsa_ctx.ecdsa_hash_sign.dst = req->dst;
	ecdsa_ctx.ecdsa_hash_sign.dst_len = req->dst_len;
	ecdsa_ctx.error_code_addr = &error_code;

	ret = intf->ecdsa_hash_sign(&ecdsa_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDSA hash sign  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to request ECDSA hash sign with sdm error code = %x\n",
			    error_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs ecdsa hash sign command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Verifies the hash using the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer,
 * and destination buffer length.
 *
 * This function verifies the hash using the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer
 * and destination buffer length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param req request structure pointer
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT
fcs_ecdsa_hash_verify(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 context_id,
		      FCS_OSAL_U32 key_id, struct fcs_ecdsa_verify_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdsa_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (req->src_len == 0) {
		FCS_LOG_ERR("Invalid argument: src_len is 0\n");
		return -EINVAL;
	}

	if (!req->signature) {
		FCS_LOG_ERR("Invalid argument: signature is NULL\n");
		return -EINVAL;
	}

	if (req->signature_len == 0) {
		FCS_LOG_ERR("Invalid argument: signature_len is 0\n");
		return -EINVAL;
	}

	if (key_id == 0) {
		if (!req->pubkey) {
			FCS_LOG_ERR("Invalid argument: pubkey is NULL\n");
			return -EINVAL;
		}

		if (req->pubkey_len == 0) {
			FCS_LOG_ERR("Invalid argument: pubkey_len is 0\n");
			return -EINVAL;
		}
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (req->dst_len == 0) {
		FCS_LOG_ERR("Invalid argument: dst_len is zero\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdsa_hash_verify) {
		FCS_LOG_ERR("ECDSA hash verify API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs ecdsa hash verify command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDSA hash verify\n");

	memcpy(ecdsa_ctx.ecdsa_hash_verify.suuid, session_uuid, FCS_OSAL_UUID_SIZE);

	ecdsa_ctx.ecdsa_hash_verify.key_id = key_id;
	ecdsa_ctx.ecdsa_hash_verify.context_id = context_id;
	ecdsa_ctx.ecdsa_hash_verify.ecc_curve = req->ecc_curve;
	ecdsa_ctx.ecdsa_hash_verify.src = req->src;
	ecdsa_ctx.ecdsa_hash_verify.src_len = req->src_len;
	ecdsa_ctx.ecdsa_hash_verify.signature = req->signature;
	ecdsa_ctx.ecdsa_hash_verify.signature_len = req->signature_len;
	ecdsa_ctx.ecdsa_hash_verify.pubkey = req->pubkey;
	ecdsa_ctx.ecdsa_hash_verify.pubkey_len = req->pubkey_len;
	ecdsa_ctx.ecdsa_hash_verify.dst = req->dst;
	ecdsa_ctx.ecdsa_hash_verify.dst_len = req->dst_len;
	ecdsa_ctx.error_code_addr = &error_code;

	ret = intf->ecdsa_hash_verify(&ecdsa_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDSA hash verify  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to request ECDSA hash verify with sdm error code = %x\n",
			    error_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs ecdsa hash verify command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Signs the data using sha2 with the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer
 * and destination buffer length.
 *
 * This function signs the data using the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer
 * and destination buffer length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_ecdsa_sha2_data_sign(FCS_OSAL_UUID *session_uuid,
				      FCS_OSAL_U32 context_id,
				      FCS_OSAL_U32 key_id,
				      struct fcs_ecdsa_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdsa_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (req->src_len == 0) {
		FCS_LOG_ERR("Invalid argument: src_len is 0\n");
		return -EINVAL;
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (req->dst_len == 0) {
		FCS_LOG_ERR("Invalid argument: dst_len is zero\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdsa_sha2_data_sign) {
		FCS_LOG_ERR("ECDSA SHA2 data sign API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs ecdsa sha2 data sign command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDSA SHA2 data sign\n");

	memcpy(ecdsa_ctx.ecdsa_sha2_data_sign.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);

	ecdsa_ctx.ecdsa_sha2_data_sign.key_id = key_id;
	ecdsa_ctx.ecdsa_sha2_data_sign.context_id = context_id;
	ecdsa_ctx.ecdsa_sha2_data_sign.ecc_curve = req->ecc_curve;
	ecdsa_ctx.ecdsa_sha2_data_sign.src = req->src;
	ecdsa_ctx.ecdsa_sha2_data_sign.src_len = req->src_len;
	ecdsa_ctx.ecdsa_sha2_data_sign.dst = req->dst;
	ecdsa_ctx.ecdsa_sha2_data_sign.dst_len = req->dst_len;
	ecdsa_ctx.error_code_addr = &error_code;

	ret = intf->ecdsa_sha2_data_sign(&ecdsa_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDSA SHA2 data sign  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to request ECDSA SHA2 data sign with sdm error code = %x\n",
			    error_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in ecdsa sha2 data sign command\n");
		return -EAGAIN;
	}

	return ret;
}

/**
 * @brief Verifies the data using sha2 with the specified session UUID, context
 * ID, key ID, ECC curve, source buffer, source buffer length,
 * destination buffer, and destination buffer length.
 *
 * This function verifies the data using the specified session UUID, context ID,
 * key ID, ECC curve, source buffer, source buffer length, destination buffer
 * and destination buffer length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT
fcs_ecdsa_sha2_data_verify(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 context_id,
			   FCS_OSAL_U32 key_id,
			   struct fcs_ecdsa_verify_req *req)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context ecdsa_ctx;
	FCS_OSAL_INT error_code = 0;

	if (!session_uuid) {
		FCS_LOG_ERR("Invalid argument: session_uuid is NULL\n");
		return -EINVAL;
	}

	if (req->ecc_curve != FCS_ECC_CURVE_NIST_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_NIST_P384 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P256 &&
	    req->ecc_curve != FCS_ECC_CURVE_BRAINPOOL_P384) {
		FCS_LOG_ERR("Invalid argument: ecc_curve\n");
		return -EINVAL;
	}

	if (!req->src) {
		FCS_LOG_ERR("Invalid argument: src is NULL\n");
		return -EINVAL;
	}

	if (req->src_len == 0) {
		FCS_LOG_ERR("Invalid argument: src_len is 0\n");
		return -EINVAL;
	}

	if (!req->signature) {
		FCS_LOG_ERR("Invalid argument: signature is NULL\n");
		return -EINVAL;
	}

	if (req->signature_len == 0) {
		FCS_LOG_ERR("Invalid argument: signature_len is 0\n");
		return -EINVAL;
	}

	if (key_id == 0) {
		if (!req->pubkey) {
			FCS_LOG_ERR("Invalid argument: pubkey is NULL\n");
			return -EINVAL;
		}

		if (req->pubkey_len == 0) {
			FCS_LOG_ERR("Invalid argument: pubkey_len is 0\n");
			return -EINVAL;
		}
	}

	if (!req->dst) {
		FCS_LOG_ERR("Invalid argument: dst is NULL\n");
		return -EINVAL;
	}

	if (req->dst_len == 0) {
		FCS_LOG_ERR("Invalid argument: dst_len is zero\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->ecdsa_sha2_data_verify) {
		FCS_LOG_ERR("ECDSA SHA2 data verify API not available\n");
		return -ENXIO;
	}

	if (MUTEX_LOCK() != 0) {
		FCS_LOG_ERR("Mutex lock failed in ecdsa sha2 data verify command\n");
		return -EAGAIN;
	}

	FCS_LOG_DBG("Requesting ECDSA SHA2 data verify\n");

	memcpy(ecdsa_ctx.ecdsa_sha2_data_verify.suuid, session_uuid,
	       FCS_OSAL_UUID_SIZE);

	ecdsa_ctx.ecdsa_sha2_data_verify.key_id = key_id;
	ecdsa_ctx.ecdsa_sha2_data_verify.context_id = context_id;
	ecdsa_ctx.ecdsa_sha2_data_verify.ecc_curve = req->ecc_curve;
	ecdsa_ctx.ecdsa_sha2_data_verify.signature = req->signature;
	ecdsa_ctx.ecdsa_sha2_data_verify.signature_len = req->signature_len;
	ecdsa_ctx.ecdsa_sha2_data_verify.pubkey = req->pubkey;
	ecdsa_ctx.ecdsa_sha2_data_verify.pubkey_len = req->pubkey_len;
	ecdsa_ctx.ecdsa_sha2_data_verify.src = req->src;
	ecdsa_ctx.ecdsa_sha2_data_verify.user_data_sz = req->src_len;
	ecdsa_ctx.ecdsa_sha2_data_verify.src_len = req->src_len;
	ecdsa_ctx.ecdsa_sha2_data_verify.dst = req->dst;
	ecdsa_ctx.ecdsa_sha2_data_verify.dst_len = req->dst_len;
	ecdsa_ctx.error_code_addr = &error_code;

	ret = intf->ecdsa_sha2_data_verify(&ecdsa_ctx);
	if (ret != 0) {
		FCS_LOG_ERR("Error in requesting ECDSA SHA2 data verify  %s\n", strerror(errno));
	} else if (error_code) {
		ret = error_code;
		FCS_LOG_ERR("Failed to request ECDSA SHA2 data verify with sdm error code = %x\n",
			    error_code);
	};

	if (MUTEX_UNLOCK() != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs ecdsa sha2 data verify command\n");
		return -EAGAIN;
	}

	return ret;
}

static FCS_OSAL_INT fcs_fit_image_hash_verify(FCS_OSAL_UUID *session_uuid,
					      FCS_OSAL_CHAR *img_data,
					      FCS_OSAL_SIZE img_data_size,
					      FCS_OSAL_CHAR *exp_hash,
					      FCS_OSAL_SIZE hash_size)
{
	FCS_OSAL_INT ret = 0;
	FCS_OSAL_CHAR *cal_hash = NULL;
	FCS_OSAL_SIZE cal_hash_size = FCS_SHA_384_DIGEST_SIZE;
	struct fcs_digest_get_req get_digest_req;

	cal_hash = (FCS_OSAL_CHAR *)fcs_malloc(FCS_SHA_384_DIGEST_SIZE);
	if (!cal_hash) {
		FCS_LOG_ERR("Error in allocating memory for image hash\n");
		return -ENOMEM;
	}

	FCS_LOG_DBG("Verifying image hash");

	get_digest_req.sha_op_mode = 1;
	get_digest_req.sha_digest_sz = 1;
	get_digest_req.src = img_data;
	get_digest_req.src_len = img_data_size;
	get_digest_req.digest = cal_hash;
	get_digest_req.digest_len = (FCS_OSAL_U32 *)&cal_hash_size;

	/* Calculate the hash of the image */
	ret = fcs_get_digest(session_uuid, 0, 0, &get_digest_req);
	if (ret < 0) {
		FCS_LOG_ERR("Error in calculating image hash\n");
		return -EINVAL;
	}

	/* Compare the calculated hash with the expected hash */
	if (memcmp(cal_hash, exp_hash, hash_size) != 0) {
		FCS_LOG_ERR("Image hash verification failed\n");
		return -EINVAL;
	}

	fcs_osal_free(cal_hash);

	return ret;
}

static inline void get_vab_cert(FCS_OSAL_CHAR *img, FCS_OSAL_SIZE img_size,
			 FCS_OSAL_CHAR **vab_cert, FCS_OSAL_UINT *vab_cert_len)
{
	FCS_OSAL_CHAR *img_end = img + img_size;
	*vab_cert_len = *(uint32_t *)(img_end - FCS_CERT_LEN_PARAM_SZ);
	*vab_cert = img_end - *vab_cert_len - FCS_CERT_LEN_PARAM_SZ;
}

static inline void get_img_data_sz(FCS_OSAL_CHAR *img, FCS_OSAL_SIZE img_size,
			    FCS_OSAL_SIZE *img_data_size)
{
	FCS_OSAL_CHAR *img_end = img + img_size;
	*img_data_size = img_end -
			 *(FCS_OSAL_U32 *)(img_end - FCS_CERT_LEN_PARAM_SZ) -
			 FCS_CERT_LEN_PARAM_SZ - img;
}

/**
 * @brief Sends the HPS VAB image certificate to the SDM requesting validation
 * of an HPS image
 *
 * @param session_uuid Pointer to the session UUID.
 * @param hps_image file pointer to the HPS image.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_validate_hps_image(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_CHAR *hps_image)
{
	FCS_OSAL_INT ret = 0;
	struct fcs_cmd_context cmd_ctx;
	FCS_OSAL_INT error_code = 0, fsize = 0, prnt_node = 0, noffset = 0,
		     ndepth = 0;
	FCS_OSAL_CHAR *vab_cert = NULL;
	FCS_OSAL_CHAR *hps_buff = NULL;
	FCS_OSAL_UINT vab_cert_len = 0;
	FCS_OSAL_U32 response = 0;

	if (!hps_image) {
		FCS_LOG_ERR("Invalid argument: hps_image is NULL\n");
		return -EINVAL;
	}

	if (ctx.state != initialized) {
		FCS_LOG_ERR("FCS library not initialized\n");
		return -EINVAL;
	}

	if (!intf->hps_img_validate) {
		FCS_LOG_ERR("HPS image validate API not available\n");
		return -ENXIO;
	}

	if (fcs_mutex_timedlock(&ctx.hps_img_verify_mutex,
				FCS_TIME_FOREVER) != 0) {
		FCS_LOG_ERR("Mutex lock failed in fcs hps img validate command\n");
		return -EAGAIN;
	}

	fsize = fcs_alloc_and_cpy_file_to_mem(hps_image, &hps_buff);
	if (fsize < 0 || !hps_buff) {
		FCS_LOG_ERR("Error in copying HPS image to memory\n");
		ret = -EINVAL;
		goto free_hps_buff;
	}

	if (!fcs_fit_verify_header(hps_buff)) {
		FCS_OSAL_CHAR *img = hps_buff;
		FCS_OSAL_SIZE img_size = fsize;
		FCS_OSAL_SIZE img_data_size = 0;

		FCS_LOG_DBG("Parsing Normal HPS image\n");

		get_vab_cert(img, img_size, (FCS_OSAL_CHAR **)&vab_cert, &vab_cert_len);
		get_img_data_sz(img, img_size, &img_data_size);

		FCS_LOG_DBG("img_size=%zd, img_dt_size=%zd, vab_cert_len=%d, magic_num=0x%x\n",
			    img_size, img_data_size, vab_cert_len,
			    *(uint32_t *)vab_cert);

		if (*(uint32_t *)vab_cert != SDM_CERT_MAGIC_NUM) {
			FCS_LOG_ERR("Invalid VAB certificate\n");
			ret = -EINVAL;
			goto free_hps_buff;
		}

		/* Verify the image hash */
		ret = fcs_fit_image_hash_verify(session_uuid, img, img_data_size,
				&((struct fcs_hps_vab_certificate *)vab_cert)->fcs_sha384[0],
				FCS_SHA_384_DIGEST_SIZE);
		if (ret < 0) {
			FCS_LOG_ERR("Error in verifying image hash noffset=%d\n", noffset);
			ret = -EINVAL;
			goto free_hps_buff;
		}

		FCS_LOG_DBG("Validating HPS image\n");
		/* Validate the VAB certificate */
		cmd_ctx.hps_img_validate.vab_cert = vab_cert;
		cmd_ctx.hps_img_validate.vab_cert_len = vab_cert_len;
		cmd_ctx.hps_img_validate.test = 0;
		cmd_ctx.hps_img_validate.resp = &response;
		cmd_ctx.error_code_addr = &error_code;

		ret = intf->hps_img_validate(&cmd_ctx);
		if (ret != 0) {
			FCS_LOG_ERR("Error in validating HPS image  %s\n", strerror(errno));
		} else if (error_code) {
			ret = error_code;
			FCS_LOG_ERR("Failed to validate HPS image with sdm error code = %x\n",
				    error_code);
		};
		FCS_LOG_DBG("HPS image validation success\n");

	} else {
		FCS_LOG_DBG("Parsing FIT image\n");
		prnt_node = fcs_fit_get_noffset(hps_buff, FIT_PARENT_NODE_PATH);
		if (prnt_node < 0) {
			FCS_LOG_ERR("Can't find images parent node '%s' (%s)\n",
				    FIT_PARENT_NODE_PATH,
				    fcs_fit_strerror(prnt_node));
			ret = -EINVAL;
			goto free_hps_buff;
		}

		FCS_LOG_DBG("prnt_node = %d\n", prnt_node);
		/* Process its subnodes, extract the desired component from image */
		noffset = fcs_fit_next_node(hps_buff, prnt_node, &ndepth);
		FCS_LOG_DBG("noffset = %d, ndepth = %d\n", noffset, ndepth);

		while (noffset >= 0) {
			if (ndepth == 1) {
				/* Process subnodes */
				FCS_OSAL_CHAR *img = NULL;
				FCS_OSAL_SIZE img_size = 0;
				FCS_OSAL_SIZE img_data_size = 0;

				FCS_LOG_DBG("extracting HPS image data noffset = %d\n",
					    noffset);
				/* Get the image data */
				ret = fcs_fit_image_get_data_and_size(hps_buff,
								      noffset,
								      &img,
								      &img_size);
				if (ret < 0) {
					FCS_LOG_ERR("Error in getting image data noffset = %d\n",
						    noffset);
					ret = -EINVAL;
					goto free_hps_buff;
				}

				get_vab_cert(img, img_size,
					     (FCS_OSAL_CHAR **)&vab_cert,
					     &vab_cert_len);
				get_img_data_sz(img, img_size, &img_data_size);

				FCS_LOG_DBG("img_size=%zd, img_dt_size=%zd, vab_cert_len=%d, magic_num = 0x%x\n",
					    img_size, img_data_size,
					    vab_cert_len,
					    *(uint32_t *)vab_cert);

				if (*(uint32_t *)vab_cert != SDM_CERT_MAGIC_NUM) {
					FCS_LOG_ERR("Invalid VAB certificate\n");
					ret = -EINVAL;
					goto free_hps_buff;
				}

				FCS_LOG_DBG("Verifying image hash noffset = %d\n", noffset);
				/* Verify the image hash */
				ret = fcs_fit_image_hash_verify(
					session_uuid, img, img_data_size,
					&((struct fcs_hps_vab_certificate *)
						  vab_cert)
						 ->fcs_sha384[0],
					FCS_SHA_384_DIGEST_SIZE);
				if (ret < 0) {
					FCS_LOG_ERR("Error in verifying image hash noffset = %d\n",
						    noffset);
					ret = -EINVAL;
					goto free_hps_buff;
				}

				FCS_LOG_DBG("Validating HPS image\n");
				/* Validate the VAB certificate */
				cmd_ctx.hps_img_validate.vab_cert = vab_cert;
				cmd_ctx.hps_img_validate.vab_cert_len = vab_cert_len;
				cmd_ctx.hps_img_validate.test = 0;
				cmd_ctx.hps_img_validate.resp = &response;
				cmd_ctx.error_code_addr = &error_code;

				ret = intf->hps_img_validate(&cmd_ctx);
				if (ret != 0) {
					FCS_LOG_ERR("Error in validating HPS image  %s\n", strerror(errno));
				} else if (error_code) {
					ret = error_code;
					FCS_LOG_ERR("Failed to validate HPS image with sdm error code = %x\n",
						    error_code);
				};

				FCS_LOG_DBG("HPS image validation success %d\n", noffset);
			}
			noffset = fcs_fit_next_node(hps_buff, noffset, &ndepth);
		}
	}

free_hps_buff:
	fcs_osal_free(hps_buff);

	if (fcs_mutex_unlock(&ctx.hps_img_verify_mutex) != 0) {
		FCS_LOG_ERR("Mutex unlock failed in fcs hps img validate command\n");
		return -EAGAIN;
	}

	return ret;
}
