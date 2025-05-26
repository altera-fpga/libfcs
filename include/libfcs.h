/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

/**
 *
 * @file libfcs.h
 * @brief Contains the public functions to be used by each application to
 * exercise libFCS functionality.
 */

#ifndef LIBFCS_H
#define LIBFCS_H

#include <libfcs_osal_types.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * Hkdf request structure
 */
struct fcs_hkdf_req {
	/* Step mode */
	FCS_OSAL_U32 step_type;
	/* Mac mode*/
	FCS_OSAL_U32 mac_mode;
	/* 1st input buffer pointer */
	FCS_OSAL_CHAR *input1;
	/* Input1 len */
	FCS_OSAL_U32 input1_len;
	/* 2nd input buffer pointer */
	FCS_OSAL_CHAR *input2;
	/* Length of 2nd input */
	FCS_OSAL_U32 input2_len;
	/* Output key object pointer */
	FCS_OSAL_CHAR *output_key_obj;
	/* Output key object length */
	FCS_OSAL_U32 output_key_obj_len;
	/* HKDF response */
	FCS_OSAL_U32 *hkdf_resp;
};

/**
 * ECDSA hash verify request structure
 */
struct fcs_ecdsa_verify_req {
	/* ECC curve */
	FCS_OSAL_U32 ecc_curve;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_len;
	/* Signature */
	FCS_OSAL_CHAR *signature;
	/* Signature length */
	FCS_OSAL_U32 signature_len;
	/* Public key */
	FCS_OSAL_CHAR *pubkey;
	/* Public key length */
	FCS_OSAL_U32 pubkey_len;
	/* Output buffer pointer */
	FCS_OSAL_CHAR *dst;
	/* Output buffer length pointer */
	FCS_OSAL_U32 *dst_len;
};

/**
 * ECDSA hash verify request structure streaming
 */
struct fcs_ecdsa_verify_req_streaming {
	/* ECC curve */
	FCS_OSAL_U32 ecc_curve;
	/* Source buffer file */
	FCS_OSAL_CHAR *src_file;
	/* Signature file*/
	FCS_OSAL_CHAR *signature_file;
	/* Public key file */
	FCS_OSAL_CHAR *pubkey_file;
	/* Output file */
	FCS_OSAL_CHAR *outfilename;
};

/**\
 * ECDA hash sign request structure
 */
struct fcs_ecdsa_req {
	/* ECC curve */
	FCS_OSAL_U32 ecc_curve;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_len;
	/* Output buffer pointer */
	FCS_OSAL_CHAR *dst;
	/* Output buffer length pointer */
	FCS_OSAL_U32 *dst_len;
};

/**
 * SDOS encryption request structure
 */
struct fcs_sdos_enc_req {
	/* Op mode */
	FCS_OSAL_U32 op_mode;
	/* Owner */
	FCS_OSAL_U64 own;
	/* ID */
	FCS_OSAL_U16 id;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_sz;
	/* Output buffer pointer */
	FCS_OSAL_CHAR *dst;
	/* Pointer to Output buffer length */
	FCS_OSAL_U32 *dst_sz;
};

/**
 * SDOS decryption request structure
 */
struct fcs_sdos_dec_req {
	/* Op mode */
	FCS_OSAL_U32 op_mode;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_sz;
	/* Padding */
	FCS_OSAL_INT pad;
	/* Output buffer pointer */
	FCS_OSAL_CHAR *dst;
	/* Pointer to Output buffer length */
	FCS_OSAL_U32 *dst_sz;
};

/**
 * Get digest request structure
 */
struct fcs_digest_get_req {
	/* Op mode */
	FCS_OSAL_U32 sha_op_mode;
	/* Digest size */
	FCS_OSAL_U32 sha_digest_sz;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_len;
	/* Pointer to digest */
	FCS_OSAL_CHAR *digest;
	/* Pointer to digest length */
	FCS_OSAL_U32 *digest_len;
};

/**
 * Get digest request structure (streaming)
 */
struct fcs_digest_req_streaming {
	/* Op mode */
	FCS_OSAL_U32 sha_op_mode;
	/* Digest size */
	FCS_OSAL_U32 sha_digest_sz;
	/* Pointer to input source file */
	FCS_OSAL_CHAR *filename;
	/* Pointer to output file */
	FCS_OSAL_CHAR *outfilename;
};

/**
 * Mac verify request structure
 */
struct fcs_mac_verify_req {
	/* Op mode */
	FCS_OSAL_U32 op_mode;
	/* Digest size */
	FCS_OSAL_U32 dig_sz;
	/* Source buffer pointer */
	FCS_OSAL_CHAR *src;
	/* Source buffer size */
	FCS_OSAL_U32 src_sz;
	/* Output buffer pointer */
	FCS_OSAL_CHAR *dst;
	/* Pointer to Output buffer length */
	FCS_OSAL_U32 *dst_sz;
	/* User data size */
	FCS_OSAL_U32 user_data_sz;
};

/**
 * Mac verify request structure
 */
struct fcs_mac_verify_req_streaming {
	/* Op mode */
	FCS_OSAL_U32 op_mode;
	/* Digest size */
	FCS_OSAL_U32 dig_sz;
	/* Pointer to input source file 1 */
	FCS_OSAL_CHAR *filename1;
	/* Pointer to input source file 2 */
	FCS_OSAL_CHAR *filename2;
	/* Pointer to output file */
	FCS_OSAL_CHAR *outfilename;
 };

/**
 * AES request structure
 */
struct fcs_aes_req {
	/* AES cryption mode */
	FCS_OSAL_U32 crypt_mode;
	/* Block mode */
	FCS_OSAL_U32 block_mode;
	/* IV source: Internal or External */
	FCS_OSAL_U32 iv_source;
	/* Pointer to IV */
	FCS_OSAL_CHAR *iv;
	/* IV length */
	FCS_OSAL_U32 iv_len;
	/* Pointer to Tag */
	FCS_OSAL_CHAR *tag;
	/* Tag length */
	FCS_OSAL_U32 tag_len;
	/* AAD length */
	FCS_OSAL_U32 aad_len;
	/* Pointer to AAD buffer */
	FCS_OSAL_CHAR *aad;
	/* Pointer to input data */
	FCS_OSAL_CHAR *input;
	/* Input data length */
	FCS_OSAL_U32 ip_len;
	/* Pointer to output buffer */
	FCS_OSAL_CHAR *output;
	/* Pointer to output buffer length */
	FCS_OSAL_U32 *op_len;
};

struct fcs_aes_req_streaming {
	/* AES cryption mode */
	FCS_OSAL_U32 crypt_mode;
	/* Block mode */
	FCS_OSAL_U32 block_mode;
	/* IV source: Internal or External */
	FCS_OSAL_U32 iv_source;
	/* Pointer to input source file */
	FCS_OSAL_CHAR *filename;
	/* Pointer to IV file */
	FCS_OSAL_CHAR *iv_file;
	/* Pointer to AAD file */
	FCS_OSAL_CHAR *aad_file;
	/* Pointer to Tag file */
	FCS_OSAL_CHAR *tag_file;
	/* Pointer to output file */
	FCS_OSAL_CHAR *outfilename;
};

/**
 * ECDH request structure
 */
struct fcs_ecdh_req {
	FCS_OSAL_U32 ecc_curve;
	FCS_OSAL_CHAR *pubkey;
	FCS_OSAL_U32 pubkey_len;
	FCS_OSAL_CHAR *shared_secret;
	FCS_OSAL_U32 *shared_secret_len;
};

/**
 * @brief Opens a service session.
 *
 * @param session_id The session ID.
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_open_service_session(FCS_OSAL_UUID *session_id);

/**
 * @brief Closes a service session.
 *
 * @param session_id Pointer to the session UUID.
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_close_service_session(FCS_OSAL_UUID *session_id);

/**
 * @brief Generates a random number.
 *
 * @param rng output buffer for generated random number.
 * @param session_id The session ID.
 * @param context_id The context ID.
 * @param rnsize The random number size.
 * @return Random number.
 */
FCS_OSAL_INT fcs_random_number_ext(FCS_OSAL_UUID *session_id,
				   FCS_OSAL_U32 context_id, FCS_OSAL_CHAR *rng,
				   FCS_OSAL_U32 rnsize);

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
				    FCS_OSAL_UINT *imp_resp_len);

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
				    FCS_OSAL_UINT *keylen);

/**
 * @brief Removes a service key identified by the given session ID.
 *
 * @param session_uuid The session ID of the key to remove.
 * @param keyid The key ID
 *
 * @return 0 on success, otherwise value on error.
 */
FCS_OSAL_INT fcs_remove_service_key(FCS_OSAL_UUID *session_uuid,
				    FCS_OSAL_U32 keyid);

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
				      FCS_OSAL_UINT *keyinfolen);

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
				    FCS_OSAL_UINT status_len);

/**
 * @brief Retrieves the provision data.
 *
 * This function retrieves the provision data for the FCS service and
 * stores it in the provided buffer.
 *
 * @param buff Pointer to the buffer where the provision data will be stored.
 * @param pd_size Pointer to the size of the buffer in bytes.
 *
 * @return The number of bytes written to the buffer, or a negative error code
 * if an error occurred.
 */
FCS_OSAL_INT fcs_service_get_provision_data(FCS_OSAL_CHAR *buff,
					    FCS_OSAL_U32 *pd_size);

/**
 * @brief Sets the service counter with the provided buffer and size.
 *
 * This function updates the service counter using the data provided
 * in the buffer.
 * It also takes a test parameter and returns a certification status.
 *
 * @param buffer Pointer to the buffer containing the data to set the
 * service counter.
 * @param size buffer size.
 * @param test An integer parameter used for testing purposes.
 * @param cert_status Pointer to a variable where the certification status will
 * be stored.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_service_counter_set(FCS_OSAL_CHAR *buffer, FCS_OSAL_INT size,
				     FCS_OSAL_INT test,
				     FCS_OSAL_CHAR *cert_status);

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
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_service_counter_set_preauthorized(FCS_OSAL_U8 type,
						   FCS_OSAL_U32 value,
						   FCS_OSAL_INT test);

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
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */

FCS_OSAL_INT fcs_hkdf_request(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 key_id,
			      struct fcs_hkdf_req *req);

/**
 * @brief Computes the digest for the specified session UUID, context ID,
 * key ID, SHA operation mode, SHA digest size, source buffer
 * and source buffer length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param keyid Key ID.
 * @param req get digest request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_get_digest(FCS_OSAL_UUID *session_uuid,
			    FCS_OSAL_U32 context_id, FCS_OSAL_U32 keyid,
			    struct fcs_digest_get_req *req);

/**
 * @brief Verifies the MAC.
 *
 * This function verifies the MAC for the specified session UUID, context ID
 * key ID, operation mode, digest size, source buffer, source buffer size
 * destination buffer, destination buffer size, and user data size.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param keyid Key ID.
 * @param req Mac verify request
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_mac_verify(FCS_OSAL_UUID *session_uuid,
			    FCS_OSAL_U32 context_id, FCS_OSAL_U32 keyid,
			    struct fcs_mac_verify_req *req);

/**
 * @brief Request AES encryption/decryption operation.
 *
 * This function requests the AES encryption/decryption operation for the
 * specified session UUID, key ID, context ID, crypt mode, block mode, IV,
 * IV length, input data, input length, output data, output length, status
 * and status length.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req aes request structure.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_aes_crypt(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 key_id,
			   FCS_OSAL_U32 context_id, struct fcs_aes_req *req);

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
			  FCS_OSAL_U32 context_id, struct fcs_ecdh_req *req);

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
FCS_OSAL_INT fcs_get_chip_id(FCS_OSAL_U32 *chip_id_lo,
			     FCS_OSAL_U32 *chip_id_hi);

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
					     FCS_OSAL_U32 *cert_size);

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
FCS_OSAL_INT fcs_attestation_certificate_reload(FCS_OSAL_INT cert_request);

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
			       FCS_OSAL_CHAR *dst, FCS_OSAL_U32 *dst_len);

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
FCS_OSAL_INT fcs_get_jtag_idcode(FCS_OSAL_U32 *jtag_idcode);

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
				     FCS_OSAL_U32 *dev_identity_length);

/**
 * @brief Requests exclusive access to the QSPI interface
 *
 * This function requests exclusive access to the QSPI interface.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_open(void);

/**
 * @brief Closes the exculsive access to the QSPI interface
 *
 * This function closes the QSPI interface.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_qspi_close(void);

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
FCS_OSAL_INT fcs_qspi_set_cs(FCS_OSAL_U32 chipsel);

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
			   FCS_OSAL_U32 len);

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
			    FCS_OSAL_U32 len);

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
FCS_OSAL_INT fcs_qspi_erase(FCS_OSAL_U32 qspi_addr, FCS_OSAL_U32 size);

/**
 * @brief Encrypts data using the specified session UUID, context ID, and
 * operation mode.
 *
 * This function encrypts the data provided in the source buffer and stores the
 * encrypted data in the destination buffer.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param context_id Context ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_sdos_encrypt(FCS_OSAL_UUID *session_uuid,
			      FCS_OSAL_U32 context_id,
			      struct fcs_sdos_enc_req *req);

/**
 * @brief Decrypts the given source data using the specified session UUID
 * and context ID.
 *
 * This function performs decryption on the provided source data (`src`)
 * and stores the result in the destination buffer (`dst`).
 * The decryption process is determined by the operation mode (`op_mode`)
 * and may involve padding as specified by the `pad` parameter.
 *
 * @param session_uuid A pointer to the session UUID used for decryption.
 * @param context_id The context ID associated with the decryption operation.
 * @param req SDOS decryption request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation
 */
FCS_OSAL_INT fcs_sdos_decrypt(FCS_OSAL_UUID *session_uuid,
			      FCS_OSAL_U32 context_id,
			      struct fcs_sdos_dec_req *req);

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
				   FCS_OSAL_U32 *pubkey_len);

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
				 struct fcs_ecdsa_req *req);

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
		      FCS_OSAL_U32 key_id, struct fcs_ecdsa_verify_req *req);

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
FCS_OSAL_INT
fcs_ecdsa_sha2_data_sign(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 context_id,
			 FCS_OSAL_U32 key_id, struct fcs_ecdsa_req *req);

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
			   struct fcs_ecdsa_verify_req *req);

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
				    FCS_OSAL_CHAR *hps_image);

/**
 * @brief Sends a generic mailbox command.
 *
 * This function sends a generic mailbox command and receives a response.
 *
 * @param mbox_cmd_code The mailbox command code.
 * @param src Pointer to the source buffer.
 * @param src_len The length of the source buffer.
 * @param dst Pointer to the destination buffer.
 * @param dst_len Pointer to the length of the destination buffer.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_mbox_send_cmd(FCS_OSAL_U32 mbox_cmd_code, FCS_OSAL_CHAR *src,
	FCS_OSAL_U32 src_len, FCS_OSAL_CHAR *dst,
	FCS_OSAL_U32 *dst_len);

/**
 * @brief Signs data using the ECDSA algorithm with SHA-2
 *
 * This function signs the data in the provided input file using the ECDSA
 * algorithm with SHA-2. The signing operation uses the key and context
 * specified in the cryptographic session, and the resulting signature is saved
 * to the specified output file.
 *
 * @param session_uuid A pointer to the session UUID that identifies the cryptographic session.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param ecc_algo The elliptic curve cryptography algorithm to be used (e.g., NIST_P256).
 * @param input_file Input file that contains the data to be signed.
 * @param output_file Output file where the signature will be saved.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT
fcs_ecdsa_data_sign(FCS_OSAL_UUID *session_uuid, FCS_OSAL_U32 context_id,
			 FCS_OSAL_U32 key_id, FCS_OSAL_INT ecc_algo,
			 FCS_OSAL_CHAR *input_file, FCS_OSAL_CHAR *output_file);

/**
 * @brief Verifies the ECDSA signature of the data in the specified file.
 *
 * This function verifies the ECDSA signature of the data in the specified
 * input file using the public key and context specified in the cryptographic
 * session. The verification result is saved to the specified output file.
 *
 * @param session_uuid A pointer to the session UUID that identifies the cryptographic session.
 * @param context_id Context ID.
 * @param key_id Key ID.
 * @param req ECDSA data verification request structure.
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_ecdsa_data_verify(FCS_OSAL_UUID *session_uuid,
				   FCS_OSAL_U32 context_id, FCS_OSAL_U32 key_id,
				   struct fcs_ecdsa_verify_req_streaming *req);

/**
 * @brief Performs AES encryption/decryption using streaming mode.
 *
 * This function performs AES encryption or decryption using streaming mode
 * for the specified session UUID, key ID, context ID, and request structure.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_aes_crypt_streaming(FCS_OSAL_UUID *session_uuid,
				     FCS_OSAL_U32 key_id,
				     FCS_OSAL_U32 context_id,
				     struct fcs_aes_req_streaming *req);

/**
 * @brief Performs digest computation using streaming mode.
 *
 * This function performs digest computation for the specified session UUID,
 * key ID, context ID, and request structure.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT fcs_get_digest_streaming(FCS_OSAL_UUID *session_uuid,
				      FCS_OSAL_U32 keyid,
				      FCS_OSAL_U32 context_id,
				      struct fcs_digest_req_streaming *req);

/**
 * @brief Verifies the MAC using streaming mode.
 *
 * This function verifies the MAC for the specified session UUID, context ID,
 * key ID, and request structure.
 *
 * @param session_uuid Pointer to the session UUID.
 * @param key_id Key ID.
 * @param context_id Context ID.
 * @param req request structure
 *
 * @return An integer returns 0 indicating the success otherwise failure of the
 * operation.
 */
FCS_OSAL_INT
fcs_mac_verify_streaming(FCS_OSAL_UUID *session_uuid,
			FCS_OSAL_U32 key_id, FCS_OSAL_U32 context_id,
			struct fcs_mac_verify_req_streaming *req);

/**
 * @brief Initializes the FCS library.
 *
 * @param loglevel set log level
 * @return 0 on success, negative value on error.
 */
FCS_OSAL_INT libfcs_init(FCS_OSAL_CHAR *loglevel);

/**
 * @brief Get the FCS library version and git SHA.
 *
 * @return Pointer to a static string with version and git SHA.
 */
const char *fcs_get_version(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
