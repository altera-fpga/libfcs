/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs_osal.h
 * @brief OS Abstraction API's used inside LibFCS.
 */

#ifndef LIBFCS_OSAL_H
#define LIBFCS_OSAL_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <libfcs_osal_types.h>

/**
 * @brief FCS OSAL time for running forever.
 */
#define FCS_TIME_FOREVER (0xFFFFFFFFUL)

/**
 * @brief FCS OSAL time for running once and return immediately.
 *
 */
#define FCS_TIME_NOWAIT (0UL)

#define SDM_CERT_MAGIC_NUM 0x25D04E7F
#define FIT_PARENT_NODE_PATH "/images"
#define FIT_DESC_PROP "description"
#define FIT_TIMESTAMP_PROP "timestamp"
#define FIT_DATA_POSITION_PROP "data-position"
#define FIT_DATA_OFFSET_PROP "data-offset"
#define FIT_DATA_PROP "data"
#define FIT_DATA_SIZE_PROP "data-size"
#if defined(CONFIG_TIMESTAMP)
#define IMAGE_ENABLE_TIMESTAMP 1
#else
#define IMAGE_ENABLE_TIMESTAMP 0
#endif

#pragma pack(push, 1)
struct fcs_cmd_context {
	/* Error status variable address */
	FCS_OSAL_INT *error_code_addr;
	union {
		struct {
			/* Session id */
			FCS_OSAL_UUID *suuid;
			FCS_OSAL_UINT *suuid_len;
		} open_session;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
		} close_session;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_CHAR *key;
			FCS_OSAL_UINT key_len;
			FCS_OSAL_CHAR *status;
			FCS_OSAL_UINT *status_len;
		} import_key;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 key_id;
			FCS_OSAL_CHAR *key;
			FCS_OSAL_UINT *key_len;
		} export_key;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 key_id;
		} remove_key;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			/* random number size */
			FCS_OSAL_U32 key_id;
			FCS_OSAL_CHAR *info;
			FCS_OSAL_UINT *info_len;
		} key_info;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_CHAR *key;
			FCS_OSAL_UINT key_len;
			FCS_OSAL_CHAR *status;
			FCS_OSAL_UINT *status_len;
		} create_key;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 step_type;
			FCS_OSAL_U32 mac_mode;
			/* Shared secret or initial secret material*/
			FCS_OSAL_CHAR *ikm;
			FCS_OSAL_U32 ikm_len;
			/* Key Derivation Key. */
			FCS_OSAL_CHAR *info;
			FCS_OSAL_U32 info_len;
			/* Output key object */
			FCS_OSAL_CHAR *output_key_obj;
			FCS_OSAL_U32 output_key_obj_len;
			/* Response status */
			FCS_OSAL_U32 *hkdf_resp;
		} hkdf_req;

		struct {
			FCS_OSAL_CHAR *data;
			FCS_OSAL_U32 *data_len;
		} prov_data;

		struct {
			FCS_OSAL_U32 cache;
			FCS_OSAL_CHAR *ccert;
			FCS_OSAL_U32 ccert_len;
			FCS_OSAL_CHAR *status;
			FCS_OSAL_UINT *status_len;
		} ctr_set;

		struct {
			FCS_OSAL_U32 ctr_type;
			FCS_OSAL_U32 ctr_val;
			FCS_OSAL_INT test;
		} ctr_set_preauth;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			/* context id */
			FCS_OSAL_U32 context_id;
			FCS_OSAL_CHAR *rng;
			FCS_OSAL_U32 rng_len;
		} rng;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_UINT cid; /* Context ID */
			FCS_OSAL_UINT kid; /* Key ID */
			FCS_OSAL_U8 mode; /* ECB/CBS/CTR */
			FCS_OSAL_U8 crypt; /* Encrypt/Decrypt */
			FCS_OSAL_U32 aad_len; /* AAD Length */
			FCS_OSAL_U16 tag_len; /* Tag length */
			FCS_OSAL_U8 iv_source; /* IV src ext/int DRNG/Int IV_BASE & keyUID */
			FCS_OSAL_CHAR *iv; /* IV */
			FCS_OSAL_CHAR *aad; /* IV */
			FCS_OSAL_CHAR *Tag; /* Tag */
			FCS_OSAL_CHAR *input; /* Input data */
			FCS_OSAL_UINT ip_len; /* Input Length */
			FCS_OSAL_CHAR *output; /* Output data */
			FCS_OSAL_UINT *op_len; /* Output Length */
		} aes;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 kid;
			FCS_OSAL_U32 cid;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *pubkey;
			FCS_OSAL_U32 pubkey_len;
			FCS_OSAL_CHAR *sh_secret;
			FCS_OSAL_U32 *sh_secret_len;
		} ecdh_req;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			/* context id */
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 sha_op_mode;
			FCS_OSAL_U32 sha_digest_sz;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_len;
			FCS_OSAL_CHAR *digest;
			FCS_OSAL_U32 *digest_len;
			FCS_OSAL_UINT stage;
		} dgst;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			/* context id */
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 sha_op_mode;
			FCS_OSAL_U32 sha_digest_sz;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_size;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_size;
			FCS_OSAL_U32 user_data_size;
		} mac_verify;

		struct {
			FCS_OSAL_U32 *chip_id_lo;
			FCS_OSAL_U32 *chip_id_hi;
		} chip_id;

		struct {
			FCS_OSAL_INT cert_request;
			FCS_OSAL_CHAR *cert;
			FCS_OSAL_U32 *cert_size;
		} attestation_cert;

		struct {
			FCS_OSAL_INT cert_request;
		} attestation_cert_reload;

		struct {
			FCS_OSAL_U32 mbox_cmd;
			FCS_OSAL_U8 urgent;
			FCS_OSAL_VOID *cmd_data;
			FCS_OSAL_U32 cmd_data_sz;
			FCS_OSAL_VOID *resp_data;
			FCS_OSAL_U32 *resp_data_sz;
		} mbox;

		struct {
			FCS_OSAL_CHAR *mctp_req;
			FCS_OSAL_U32 mctp_req_len;
			FCS_OSAL_CHAR *mctp_resp;
			FCS_OSAL_U32 *mctp_resp_len;
		} mctp;

		struct {
			FCS_OSAL_U32 *jtag_idcode;
		} jtag_id;

		struct {
			FCS_OSAL_CHAR *identity;
			FCS_OSAL_U32 *identity_len;
		} device_identity;

		struct {
			FCS_OSAL_U32 chipsel;
		} qspi_cs;

		struct {
			FCS_OSAL_U32 qspi_addr;
			FCS_OSAL_U32 len;
			FCS_OSAL_CHAR *buffer;
			FCS_OSAL_U32 *buffer_len;
		} qspi_read, qspi_write;

		struct {
			FCS_OSAL_U32 qspi_addr;
			FCS_OSAL_U32 len;
		} qspi_erase;

		struct {
			/* Session id */
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			/* context id */
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 op_mode;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_size;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_size;
			FCS_OSAL_U16 id;
			FCS_OSAL_U64 own;
			FCS_OSAL_INT pad;
		} sdos;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *pubkey;
			FCS_OSAL_U32 *pubkey_len;
		} ecdsa_pub_key;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_len;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_len;
		} ecdsa_hash_sign;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_len;
			FCS_OSAL_CHAR *signature;
			FCS_OSAL_U32 signature_len;
			FCS_OSAL_CHAR *pubkey;
			FCS_OSAL_U32 pubkey_len;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_len;
		} ecdsa_hash_verify;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_len;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_len;
		} ecdsa_sha2_data_sign;

		struct {
			FCS_OSAL_UUID suuid[FCS_OSAL_UUID_SIZE];
			FCS_OSAL_U32 context_id;
			FCS_OSAL_U32 key_id;
			FCS_OSAL_U32 ecc_curve;
			FCS_OSAL_CHAR *signature;
			FCS_OSAL_U32 signature_len;
			FCS_OSAL_CHAR *pubkey;
			FCS_OSAL_U32 pubkey_len;
			FCS_OSAL_U32 user_data_sz;
			FCS_OSAL_CHAR *src;
			FCS_OSAL_U32 src_len;
			FCS_OSAL_CHAR *dst;
			FCS_OSAL_U32 *dst_len;
		} ecdsa_sha2_data_verify;

		struct {
			FCS_OSAL_CHAR *vab_cert;
			FCS_OSAL_U32 vab_cert_len;
			FCS_OSAL_U32 test;
			FCS_OSAL_U32 *resp;
		} hps_img_validate;
	};
};

#pragma pack(pop)

/*
 * struct fcs_hps_vab_certificate_header
 * @cert_magic_num: Certificate Magic Word (0x25D04E7F)
 * @cert_data_sz: size of this certificate header (0x80)
 *	Includes magic number all the way to the certificate
 *      signing keychain (excludes cert. signing keychain)
 * @cert_ver: Certificate Version
 * @cert_type: Certificate Type
 * @data: VAB HPS Image Certificate data
 */
struct fcs_hps_vab_certificate {
	FCS_OSAL_U32 cert_magic_num;
	FCS_OSAL_U32 cert_data_sz;
	FCS_OSAL_U32 cert_ver;
	FCS_OSAL_U32 cert_type;
	FCS_OSAL_U32 rsvd0_0;
	FCS_OSAL_U32 flags;
	FCS_OSAL_U8 rsvd0_1[8];
	FCS_OSAL_CHAR fcs_sha384[FCS_SHA_384_DIGEST_SIZE];
};

/**
 * @brief osal interface structure
 * @note This structure is used to hold the OSAL function pointers.
 */
struct libfcs_osal_intf {
	FCS_OSAL_INT (*open_service_session)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*close_service_session)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*random_number_ext)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*import_service_key)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*export_service_key)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*remove_service_key)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_service_key_info)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*create_service_key)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_provision_data)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*counter_set)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*counter_set_preauthorized)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*hkdf_request)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*aes_crypt)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdh_req)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_digest)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*mac_verify)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_chip_id)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*attestation_get_certificate)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*attestation_cert_reload)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*mctp_cmd_send)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_jtag_idcode)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*get_device_identity)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_open)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_close)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_cs)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_read)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_write)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*qspi_erase)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*sdos_encrypt)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*sdos_decrypt)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdsa_get_pub_key)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdsa_hash_sign)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdsa_hash_verify)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdsa_sha2_data_sign)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*ecdsa_sha2_data_verify)(struct fcs_cmd_context *ctx);
	FCS_OSAL_INT (*hps_img_validate)(struct fcs_cmd_context *ctx);
};

/**
 * @brief allocate a buffer in heap memory
 *
 * @param[in] size required heap memory size in bytes.
 * @return NUll on error or pointer to allocated memory.
 */
FCS_OSAL_VOID *fcs_malloc(FCS_OSAL_SIZE size);

/**
 * @brief free allocated heap memory.
 *
 * @param[in] ptr pointer to heap memory
 * @return Nil
 */
FCS_OSAL_VOID fcs_osal_free(FCS_OSAL_VOID *ptr);

/**
 * @brief Initialize a mutex
 *
 * @param[in] mutex pointer to a mutex object of type FCS_OSAL_MUTEX.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_mutex_init(FCS_OSAL_MUTEX *mutex);

/**
 * @brief Lock a mutex within a time period
 *
 * @note time can also be the below values @ref FCS_TIME_FOREVER
 * and @ref FCS_TIME_NOWAIT.
 *
 * @param[in] mutex pointer to a mutex object of type FCS_OSAL_MUTEX.
 * @param[in] time period by which the mutex locking should complete.
 * time is in milliseconds.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_mutex_timedlock(FCS_OSAL_MUTEX *mutex,
				 FCS_OSAL_U32 const time);

/**
 * @brief Unlock a locked mutex
 *
 * @param[in] mutex pointer to a mutex object of type FCS_OSAL_MUTEX.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_mutex_unlock(FCS_OSAL_MUTEX *mutex);

/**
 * @brief allocate memory for the buffer and copy the file content to the buffer
 *
 * @param filename file name to read
 * @param buffer to copy the file content
 * @return FCS_OSAL_INT
 */
FCS_OSAL_INT fcs_alloc_and_cpy_file_to_mem(const FCS_OSAL_CHAR *filename,
					   FCS_OSAL_CHAR **buffer);

/**
 * @brief destroy a mutex object and free up resources.
 *
 * @param[in] mutex pointer to a mutex object of type FCS_OSAL_MUTEX.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT fcs_mutex_destroy(FCS_OSAL_MUTEX *mutex);

/**
 * @brief returns fdt error message for the given error code
 */
const FCS_OSAL_CHAR *fcs_fit_strerror(FCS_OSAL_INT err);

/**
 * @brief Verify the FIT image header.
 *
 * @param fit Pointer to the FIT buffer.
 * @param size FIT size.
 *
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT fcs_fit_verify_header(FCS_OSAL_CHAR *fit);

/**
 * @brief Get the position of the node in the FIT image
 * @param fit - pointer to the FIT format image header
 * @param path - path to the node
 *
 * @return offset to the node
 */
FCS_OSAL_INT fcs_fit_get_noffset(FCS_OSAL_CHAR *fit, const FCS_OSAL_CHAR *path);

/**
 * @brief Get the next node in the FIT image
 * @param fit - pointer to the FIT format image header
 * @param offset - offset to the node
 * @param depth - pointer to store the depth
 *
 * @return offset to the next node
 */

FCS_OSAL_INT fcs_fit_next_node(FCS_OSAL_CHAR *fit, FCS_OSAL_INT offset,
			       FCS_OSAL_INT *depth);
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
					     FCS_OSAL_SIZE *size);

/**
 * @brief Bind the OSAL APIs
 *
 * @param[in] intf pointer to the OSAL interface structure.
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT libfcs_osal_api_binding(struct libfcs_osal_intf *intf);

/**
 * @brief Initialize the OSAL
 *
 * @param[in] intf pointer to the OSAL interface structure.
 * @param[in] loglevel set log level
 *
 * @return 0 on success, negative number on error.
 */
FCS_OSAL_INT libfcs_osal_init(struct libfcs_osal_intf *intf,
			      FCS_OSAL_CHAR *loglevel);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
