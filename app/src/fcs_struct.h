/* SPDX-License-Identifier: MIT-0 */
/*
 * Copyright (C) 2025 Altera
 */

#ifndef FCS_STRUCTS_H
#define FCS_STRUCTS_H

#include <stdint.h>

#define SHA256_SZ		32
#define SHA384_SZ		48

/*
 * struct fcs_hash_256 - structure of vab hash256
 * @owner_root_hash: value of owner root hash
 * @cancel_status: cancellation status. (each bit for 1 key)
 */
struct fcs_hash_256 {
	FCS_OSAL_U8  owner_root_hash[SHA256_SZ];
	FCS_OSAL_U32  cancel_status;
};

/*
 * struct fcs_hash_384 - structure of vab hash384
 * @owner_root_hash: value of owner root hash
 * @cancel_status: cancellation status (each bit for 1 key)
 */
struct fcs_hash_384 {
	FCS_OSAL_U8  owner_root_hash[SHA384_SZ];
	FCS_OSAL_U32  cancel_status;
};

/*
 * enum fcs_hash_type - enumeration of hash types
 * @INTEL_FCS_HASH_SECP256: Hash type is SHA256
 * @INTEL_FCS_HASH_SECP384R1: Hash type is SHA384
 */
enum fcs_hash_type {
	INTEL_FCS_HASH_SECP256 = 1,
	INTEL_FCS_HASH_SECP384R1 = 2
};

/*
 * struct fcs_get_provision_header - Header of provision data
 * @provision_status: 0 = no provision done, 1 = successful provision
 *		      2 = provision error
 * @intel_key_status: 0 = No cancellation, 1 = cancelled
 * @test: Flag. when set don't write fuses, write to cache only
 * @co_sign_status: 0 = Not co-signed, 1 = co-signed
 * @root_hash_status: 0 = No cancellation, 1 = cancelled
 *	Bit 0 for root hash 0
 *	Bit 1 for root hash 1
 *	Bit 2 for root hash 2
 * @num_hashes: value from 1 to 3.
 * @type_hash: 1 = secp256; 2=secp384r1 (corresponds to command)
 */
struct fcs_get_provision_header {
#ifdef LITTLE_ENDIAN
	FCS_OSAL_U32  provision_status;
	FCS_OSAL_U32  intel_key_status;
	FCS_OSAL_U32  type_hash:8;
	FCS_OSAL_U32  num_hashes:8;
	FCS_OSAL_U32  root_hash_status:3;
	FCS_OSAL_U32  co_sign_status:1;
	FCS_OSAL_U32  rsvd:12;
#else
	FCS_OSAL_U32  provision_status;
	FCS_OSAL_U32  intel_key_status;
	FCS_OSAL_U32  rsvd:12;
	FCS_OSAL_U32  co_sign_status:1;
	FCS_OSAL_U32  root_hash_status:3;
	FCS_OSAL_U32  num_hashes:8;
	FCS_OSAL_U32  type_hash:8;
#endif
};

/*
 * struct fcs_get_counters_keyslots_data - counter and keyslots data
 * @big_cntr_base_value
 * @big_cntr_count_value
 * @svn_count_val3
 * @svn_count_val2
 * @svn_count_val1
 * @svn_count_val0
 * @reserved_key_slot5
 * @reserved_key_slot4
 * @reserved_key_slot3
 * @reserved_key_slot2
 * @service_root_key_slot_1: Service Root Key #1 fuse status:
 *	0000 = Do not use (to cover old FW encoding)
 *	0001 = Key slot fuse is available
 *	0010 = Key slot fuse contains a cancelled key
 *	1111 = Key slot fuse contains a Service Root Key
 * @service_root_key_slot_0: Service Root Key #0 fuse status:
 *	0000 = Do not use (to cover old FW encoding)
 *	0001 = Key slot fuse is available
 *	0010 = Key slot fuse contains a cancelled key
 *	1111 = Key slot fuse contains a Service Root Key
 * @reserved_key_slot1
 */
struct fcs_get_counters_keyslots_data {
#ifdef LITTLE_ENDIAN
	FCS_OSAL_U32  big_cntr_count_value:24;
	FCS_OSAL_U32  big_cntr_base_value:8;
	FCS_OSAL_U8   svn_count_val0;
	FCS_OSAL_U8   svn_count_val1;
	FCS_OSAL_U8   svn_count_val2;
	FCS_OSAL_U8   svn_count_val3;
	/* Match with SDM SPEC1.5 */
	FCS_OSAL_U8   efuse_ifp_key_slot0:4;
	FCS_OSAL_U8   efuse_ifp_key_slot1:4;
	FCS_OSAL_U8   efuse_ifp_key_slot2:4;
	FCS_OSAL_U8   efuse_ifp_key_slot3:4;
	FCS_OSAL_U8   efuse_ifp_key_slot4:4;
	FCS_OSAL_U8   efuse_ifp_key_slot5:4;
	FCS_OSAL_U8   reserved_efuse_key_slot6;
	FCS_OSAL_U8   flash_ifp_key_slot0:4;
	FCS_OSAL_U8   flash_ifp_key_slot1:4;
	FCS_OSAL_U8   flash_ifp_key_slot2:4;
	FCS_OSAL_U8   flash_ifp_key_slot3:4;
	FCS_OSAL_U8   flash_ifp_key_slot4:4;
	FCS_OSAL_U8   flash_ifp_key_slot5:4;
	FCS_OSAL_U8   reserved_flash_key_slot6;
	FCS_OSAL_U32  fpm_ctr_counter:8;
	FCS_OSAL_U32  reserved_fpm:24;
#else
	FCS_OSAL_U32  big_cntr_base_value:8;
	FCS_OSAL_U32  big_cntr_count_value:24;
	FCS_OSAL_U8   svn_count_val3;
	FCS_OSAL_U8   svn_count_val2;
	FCS_OSAL_U8   svn_count_val1;
	FCS_OSAL_U8   svn_count_val0;
	/* Match with SDM SPEC1.5 */
	FCS_OSAL_U8   reserved_efuse_key_slot6;
	FCS_OSAL_U8   efuse_ifp_key_slot5:4;
	FCS_OSAL_U8   efuse_ifp_key_slot4:4;
	FCS_OSAL_U8   efuse_ifp_key_slot3:4;
	FCS_OSAL_U8   efuse_ifp_key_slot2:4;
	FCS_OSAL_U8   efuse_ifp_key_slot1:4;
	FCS_OSAL_U8   efuse_ifp_key_slot0:4;
	FCS_OSAL_U8   reserved_flash_key_slot6;
	FCS_OSAL_U8   flash_ifp_key_slot5:4;
	FCS_OSAL_U8   flash_ifp_key_slot4:4;
	FCS_OSAL_U8   flash_ifp_key_slot3:4;
	FCS_OSAL_U8   flash_ifp_key_slot2:4;
	FCS_OSAL_U8   flash_ifp_key_slot1:4;
	FCS_OSAL_U8   flash_ifp_key_slot0:4;
	FCS_OSAL_U32  reserved_fpm:24;
	FCS_OSAL_U32  fpm_ctr_counter:8;
#endif
};

/*
 * struct fcs_get_provision_data - result of get_provision_data command
 * @header: header data.
 * the hash are different sizes and will depend on the header.type_hash value.
 * @hash_256: hash256 array (can be 1 to 3 elements)
 * @hash_384: hash384 array (can be 1 to 3 elements)
 * @counters: The data counters
 */
struct fcs_get_provision_data {
	struct fcs_get_provision_header header;
	/* Depends on whether type hash is 256 or 384 */
	union {
		struct fcs_hash_256 hash_256[3];	/* May be 1 to 3 */
		struct fcs_hash_384 hash_384[3];	/* May be 1 to 3 */
	} hash;
	struct fcs_get_counters_keyslots_data counters;
};

/*
 * struct fcs_aes_crypt_header
 * @magic_number: different for input or output buffer
 *	input = 0xACBDBDED
 *	output = 0x53424112
 * @data_len: length of the data to encrypt/decrypt
 * @pad: length of padding in bytes
 * @srk_indx: service root key index has the value 0
 * @app_spec_obj_info: Application Specific Object Info
 * @owner_id: Used for key derivation
 * @hdr_pad: Header Padding: 0x01020304
 * @iv_field: output data to store the generated IV
 */
struct fcs_aes_crypt_header {
	FCS_OSAL_U32  magic_number;
	FCS_OSAL_U32  data_len;
	FCS_OSAL_U8   pad;
	FCS_OSAL_U8   srk_indx;
	uint16_t  app_spec_obj_info;
	FCS_OSAL_U8   owner_id[8];
	FCS_OSAL_U32  hdr_pad;
	FCS_OSAL_U8  iv_field[16];
};

#endif
