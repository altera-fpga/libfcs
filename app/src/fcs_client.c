// SPDX-License-Identifier: MIT-0
/*
 * Copyright (C) 2025 Altera
 */

#include <libfcs.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fcs_struct.h"

/* Commmand request/response sizes */
#define CRYPTO_EXPORTED_KEY_OBJECT_MAX_SZ	364
#define CRYPTO_HKDF_RESPONSE_MAX_SZ		64
#define CRYPTO_HKDF_OBJECT_MAX_SZ		384
#define CRYPTO_GET_KEY_INFO_MAX_SZ		144
#define CRYPTO_MAX_SZ				0x400000
#define CRYPTO_DIGEST_MAX_SZ			CRYPTO_MAX_SZ
#define ECDSA_PUB_KEY_MAX_SZ			CRYPTO_MAX_SZ
#define ECDSA_SIGNATURE_MAX_SZ			CRYPTO_MAX_SZ
#define ATTESTATION_CERTIFICATE_RSP_MAX_SZ	4096
#define MCTP_RSP_MAX_SZ				1024
#define JTAG_ID_MAX_SZ				1024
#define DEVICE_IDENTITY_MAX_SZ			1024
#define RANDOM_NUMBER_MAX_SZ			4080

/* default cert status*/
#define FCS_CERT_STATUS_NONE			0xFFFFFFFF

/* Mail Box Response Codes */
#define MBOX_RESP_AUTHENTICATION_FAIL		0X0A
#define MBOX_RESP_INVALID_CERTIFICATE		0X80
#define NOT_ALLOWED_UNDER_SECURITY_SETTINGS	0x85

/* Certificate Process Status */
#define AUTHENTICATION_FAILED			0xF0000003
#define DEV_NOT_OWNED				0xF0000004
#define INTEL_CERT_STATUS_NONE			0xFFFFFFFF

/* SDOS operations*/
#define SDOS_PLAINDATA_MIN_SZ			32
#define SDOS_PLAINDATA_MAX_SZ			32672
#define SDOS_HEADER_SZ				40
#define SDOS_HMAC_SZ				48
#define SDOS_MAGIC_WORD				0xACBDBDED
#define SDOS_HEADER_PADDING			0x01020304

/* SDOS Decryption minimum and maximum size */
#define SDOS_DECRYPTED_MIN_SZ		(SDOS_PLAINDATA_MIN_SZ + SDOS_HEADER_SZ)
#define SDOS_DECRYPTED_MAX_SZ		(SDOS_PLAINDATA_MAX_SZ + SDOS_HEADER_SZ)

/* SDOS Encryption minimum and maximum size */
#define SDOS_ENCRYPTED_MIN_SZ \
	(SDOS_PLAINDATA_MIN_SZ + SDOS_HEADER_SZ + SDOS_HMAC_SZ)
#define SDOS_ENCRYPTED_MAX_SZ \
	(SDOS_PLAINDATA_MAX_SZ + SDOS_HEADER_SZ + SDOS_HMAC_SZ)

/**
 * Represents a UUID structure
 */
struct uuid_t {
	/* Low field of timestamp */
	uint32_t time_low;
	/* Mid field of timestamp */
	uint16_t time_mid;
	/* High field of timestamp and version information */
	uint16_t time_hi_and_version;
	/* High byte of clock sequence */
	uint8_t  clock_seq_hi_and_reserved;
	/* Low byte of clock sequence */
	uint8_t  clock_seq_low;
	/* Mode field */
	uint8_t  node[6];
};

/**
 * fcs_command_code - support fpga crypto service commands
 */
enum fcs_command_code {
	/* FCS COMMAND NONE */
	FCS_DEV_COMMAND_NONE,
	/* Validate HPS Image */
	FCS_DEV_VALIDATE_REQUEST_CMD,
	/* Counter set command */
	FCS_DEV_COUNTER_SET_CMD,
	/* Counter set preauth command */
	FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD,
	/* Get provisioned data information */
	FCS_DEV_GET_PROVISION_DATA_CMD,
	/* SDOS Encryption */
	FCS_DEV_DATA_ENCRYPTION_CMD,
	/* SDOS Decryption */
	FCS_DEV_DATA_DECRYPTION_CMD,
	/* Generate Random Number */
	FCS_DEV_RANDOM_NUMBER_GEN_CMD,
	/* Get device Chip ID */
	FCS_DEV_CHIP_ID_CMD,
	/* Get device attestation certificate */
	FCS_DEV_ATTESTATION_GET_CERTIFICATE_CMD,
	/* Attestation certificate reload command */
	FCS_DEV_ATTESTATION_CERTIFICATE_RELOAD_CMD,
	/* Open a service session with SDM */
	FCS_DEV_CRYPTO_OPEN_SESSION_CMD,
	/* Close a service session with SDM */
	FCS_DEV_CRYPTO_CLOSE_SESSION_CMD,
	/* Import a key object */
	FCS_DEV_CRYPTO_IMPORT_KEY_CMD,
	/* Export a key object */
	FCS_DEV_CRYPTO_EXPORT_KEY_CMD,
	/* Remove a key object */
	FCS_DEV_CRYPTO_REMOVE_KEY_CMD,
	/* Get a key information */
	FCS_DEV_CRYPTO_GET_KEY_INFO_CMD,
	/* Create a key object */
	FCS_DEV_CRYPTO_CREATE_KEY_CMD,
	/* AES encryption/decryption command */
	FCS_DEV_CRYPTO_AES_CRYPT_CMD,
	/* Get digest */
	FCS_DEV_CRYPTO_GET_DIGEST_CMD,
	/* HMAC verify */
	FCS_DEV_CRYPTO_MAC_VERIFY_CMD,
	/* ECDSA hash signing request */
	FCS_DEV_CRYPTO_ECDSA_HASH_SIGNING_CMD,
	/* ECDSA sha2 data signing request */
	FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_SIGNING_CMD,
	/* ECDSA hash verify request */
	FCS_DEV_CRYPTO_ECDSA_HASH_VERIFY_CMD,
	/* ECDSA sha2 data verify request */
	FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_VERIFY_CMD,
	/* Get ECDSA public key */
	FCS_DEV_CRYPTO_ECDSA_GET_PUBLIC_KEY_CMD,
	/* ECDH shared secret */
	FCS_DEV_CRYPTO_ECDH_REQUEST_CMD,
	/* hkdf request */
	FCS_DEV_CRYPTO_HKDF_REQUEST_CMD,
	/* MCTP request */
	FCS_DEV_CRYPTO_MCTP_REQUEST_CMD,
	/* JTAG ID code */
	FCS_DEV_CRYPTO_GET_JTAG_ID_CMD,
	/* Get a device identity */
	FCS_DEV_CRYPTO_GET_DEVICE_IDENTITY_CMD,
	/* QSPI open */
	FCS_DEV_CRYPTO_QSPI_OPEN_CMD,
	/* QSPI close */
	FCS_DEV_CRYPTO_QSPI_CLOSE_CMD,
	/* QSPI set chip select */
	FCS_DEV_CRYPTO_QSPI_CS_CMD,
	/* QSPI read operation */
	FCS_DEV_CRYPTO_QSPI_READ_CMD,
	/* QSPI write operation */
	FCS_DEV_CRYPTO_QSPI_WRITE_CMD,
	/* QSPI erase operation */
	FCS_DEV_CRYPTO_QSPI_ERASE_CMD,
};

/**
 * option_ops - translate the long options to short options
 *
 * The main commands are uppercase. The extras are lowercase.
 *
 */
static const struct option opts[] = {
	{"counter_set_preauthorized", no_argument, NULL, 'A'},
	{"import_service_key", no_argument, NULL, 'B'},
	{"counter_set", required_argument, NULL, 'C'},
	{"aes_decrypt", no_argument, NULL, 'D'},
	{"aes_encrypt", no_argument, NULL, 'E'},
	{"get_certificate", required_argument, NULL, 'F'},
	{"get_provision_data", required_argument, NULL, 'G'},
	{"export_service_key", no_argument, NULL, 'H'},
	{"get_chipid", no_argument, NULL, 'I'},
	{"remove_service_key", no_argument, NULL, 'J'},
	{"get_service_key_info", no_argument, NULL, 'K'},
	{"certificate_reload", required_argument, NULL, 'L'},
	{"get_measurement", no_argument, NULL, 'M'},
	{"get_digest", no_argument, NULL, 'N'},
	{"mac_verify", no_argument, NULL, 'O'},
	{"ecdsa_hash_sign", no_argument, NULL, 'P'},
	{"ecdsa_sha2_data_sign", no_argument, NULL, 'Q'},
	{"random", required_argument, NULL, 'R'},
	{"get_subkey", no_argument, NULL, 'S'},
	{"psgsigma_teardown", no_argument, NULL, 'T'},
	{"ecdsa_hash_verify", no_argument, NULL, 'U'},
	{"validate", required_argument, NULL, 'V'},
	{"ecdsa_sha2_data_verify", no_argument, NULL, 'W'},
	{"ecdh_request", no_argument, NULL, 'X'},
	{"aes_crypt", no_argument, NULL, 'Y'},
	{"ecdsa_get_pub_key", no_argument, NULL, 'Z'},
	{"counter_value", required_argument, NULL, 'a'},
	{"block_mode", required_argument, NULL, 'b'},
	{"cache", required_argument, NULL, 'c'},
	{"own_id", required_argument, NULL, 'd'},
	{"open_session", no_argument, NULL, 'e'},
	{"iv_field", required_argument, NULL, 'f'},
	{"sha_op_mode", required_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"in_filename", required_argument, NULL, 'i'},
	{"sha_digest_sz", required_argument, NULL, 'j'},
	{"key_uid", required_argument, NULL, 'k'},
	{"close_session", no_argument, NULL, 'l'},
	{"aes_crypt_mode", required_argument, NULL, 'm'},
	{"context_id", required_argument, NULL, 'n'},
	{"out_filename", required_argument, NULL, 'o'},
	{"print", no_argument, NULL, 'p'},
	{"ecc_algorithm", required_argument, NULL, 'q'},
	{"own_hash", required_argument, NULL, 'r'},
	{"sessionid", required_argument, NULL, 's'},
	{"type", required_argument, NULL, 't'},
	{"iv_file", required_argument, NULL, 'u'},
	{"verbose", required_argument, NULL, 'v'},
	{"create_service_key", no_argument, NULL, 'x'},
	{"counter_type", required_argument, NULL, 'y'},
	{"in_filename_list", required_argument, NULL, 'z'},
	{"hkdf_request", no_argument, NULL, 4},
	{"step_type", required_argument, NULL, 5},
	{"mac_mode", required_argument, NULL, 6},
	{"mctp_req", no_argument, NULL, 7},
	{"get_jtag_id", no_argument, NULL, 8},
	{"get_device_identity", no_argument, NULL, 9},
	{"qspi_open", no_argument, NULL, 10},
	{"qspi_close", no_argument, NULL, 11},
	{"qspi_chipsel", required_argument, NULL, 12},
	{"qspi_read", no_argument, NULL, 13},
	{"addr", required_argument, NULL, 14},
	{"len", required_argument, NULL, 15},
	{"qspi_write", no_argument, NULL, 16},
	{"qspi_erase", no_argument, NULL, 17},
	{"hkdf_key_obj", required_argument, NULL, 18},
	{"loglevel", required_argument, NULL, 19},
	{NULL, 0, NULL, 0}
};

/**
 * fcs_client_usage() - show the usage of client application
 *
 * This function doesn't have a return value.
 */
static void fcs_client_usage(void)
{
	printf("\n--- FPGA Crypto Services Client app usage ---\n\n");
	printf("%-32s  %s", "-V|--validate <filename> -s|--sessionid <sessionid>\n",
	       "\tValidate an HPS or bitstream image\n\n");
	printf("%-32s  %s %s", "-C|--counter_set <signed_file> -c|--cache <0|1>\n",
	       "\tSet the counter value - requires signed file as parameter and\n",
	       "\twrite to cache instead of fuses if --cache set to 1\n\n");
	printf("%-32s  %s %s", "-A|counter_set_preauthorized -y <counter_type> -a <counter_value> -c <0|1>\n",
	       "\tUpdate the counter value for the selected counter without single certificate\n",
	       "\tbe activated only when the counter value is set to -1 at authorization certificate\n\n");
	printf("%-32s  %s", "-G|--get_provision_data <output_filename> -p|--print\n",
	       "\tGet the provisioning data from SDM\n\n");
	printf("%-32s  %s %s %s", "-E|--aes_encrypt -i <input_filename> -o <output_filename> -r <owner_id> -d <ASOI> -s <sid> -n <cid>\n",
	       "\tAES Encrypt a buffer of up to 32K-96 bytes - requires 8 bytes owner_id\n",
	       "\tand Applications Specific Object Info(unique 2 bytes identifier)\n",
	       "\tSend session based request if session id and context id are provided\n\n");
	printf("%-32s  %s %s", "-D|--aes_decrypt -i <input_filename> -o|--out_filename <output_filename> -s <sid> -n <cid>\n",
	       "\tAES Decrypt a buffer of up to 32K-96 bytes\n",
	       "\tSend session based request if session id and context id are provided\n\n");
	printf("%-32s  %s  %s", "-R|--random <output_filename> -s|--sessionid <sessionid> -n|--context_id <context_id> -j <size>\n",
	       "\tReturn random data with input size if session id and context id are provided\n",
	       "\tOtherwise, return up to a 32-byte of random data if session id is not provided\n\n");
	printf("%-32s  %s", "-I|--get_chipid", "get the device chipID\n\n");
	printf("%-32s  %s", "-F|--get_certificate <cer_request> -o <output_filename>\n",
	       "\tGet the FPGA attestation certificate\n\n");
	printf("%-32s  %s", "-L|--certificate_reload <cer_request>\n",
	       "\tFPGA attestation certificate on reload\n\n");
	printf("%-32s  %s", "-e|--open_session",
	       "Open crypto service session\n\n");
	printf("%-32s  %s", "-l|--close_session -s|--sessionid <sessionid>\n",
	       "\tClose crypto service session\n\n");
	printf("%-32s  %s", "-B|--import_service_key -s|--sessionid <sessionid> -i <input_filename>\n",
	       "\tImport crypto service key to the device\n\n");
	printf("%-32s  %s", "-H|--export_service_key -s|--sessionid <sessionid> -k|--key_uid <kid> -o <output_filename>\n",
	       "\tExport crypto service key to output_filename\n\n");
	printf("%-32s  %s", "-J|--remove_service_key -s|--sessionid <sessionid> -k|--key_uid <kid>\n",
	       "\tRemove crypto service key from the device\n\n");
	printf("%-32s  %s", "-K|--get_service_key_info -s|--sessionid <sessionid> -k|--key_uid <kid> -o <output_filename>\n",
	       "\tGet crypto service key info\n\n");
	printf("%-32s  %s", "-x|--create_service_key -s|--sessionid <sessionid> -i <input_filename>\n",
	       "\tCreate crypto service key to the device\n\n");
	printf("%-32s  %s", "-Y|--aes_crypt -s <sid> -n <cid> -k <kid> -b <b_mode> -m <en/decrypt> -f <iv_file> -u <aad_file> -i <input_filename> -o <output_filename>\n",
	       "\tAES encrypt (select m as 0) or decrypt (select m as 1) using crypto service key\n\n");
	printf("%-32s  %s", "-N|--get_digest -s <sid> -n <cid> -k <kid> -g <sha_op_mode> -j <dig_sz> -i <input_filename> -o <output_filename>\n",
	       "\tRequest the SHA-2 hash digest on a blob\n\n");
	printf("%-32s  %s", "-O|--mac_verify -s <sid> -n <cid> -k <kid> -j <dig_sz> -z <data.bin#mac.bin> -o <output_filename>\n",
	       "\tCheck the integrity and authenticity of a blob using HMAC\n\n");
	printf("%-32s  %s", "-P|--ecdsa_hash_sign -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -i <input_filename> -o <output_filename>\n",
	       "\tSend ECDSA digital signature signing request on a data blob\n\n");
	printf("%-32s  %s", "-Q|--ecdsa_sha2_data_sign -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -i <input_filename> -o <output_filename>\n",
	       "\tSend ECDSA signature signing request on a data blob\n\n");
	printf("%-32s  %s", "-U|--ecdsa_hash_verify -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -z <hash.bin#sigture.bin#pubkey.bin> -o <output_filename>\n",
	       "\tSend ECDSA digital signature verify request with precalculated hash\n\n");
	printf("%-32s  %s", "-W|--ecdsa_sha2_data_verify -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -z <data.bin#sigture.bin#pubkey.bin> -o <output_filename>\n",
	       "\tSend ECDSA digital signature verify request on a data blob\n\n");
	printf("%-32s  %s", "-Z|--ecdsa_get_pub_key -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -o <output_filename>\n",
	       "\tSend the request to get the public key and save public key data into the output_filename\n\n");
	printf("%-32s  %s", "-X|--ecdh_request -s <sid> -n <cid> -k <kid> -q <ecc_algorithm> -i <input_filename> -o <output_filename>\n",
	       "\tSend the request on generating a share secret on Diffie-Hellman key exchange\n\n");
	printf("%-32s  %s", "--hkdf_request -s <sid> -k <kid> --step_type <step-type> --mac_mode <> -z input1#input2#hkdf_out.obj -o <output_filename>\n",
	       "\tSend the request on performing HKDF extract or expand according to prepared input file\n\tstep-type :\n\t\t0 - EXTRACT then EXPAND\n\t\t1 - EXPAND Only (non-GCM)\n\t\t2 - EXPAND Only (GCM)\n\tmac_mode :\n\t\t0 – SHA2-256 (block size 512, reserved)\n\t\t1 – SHA2-384 (block size 1024)\n\t\t2 – SHA2-512 (block size 1024, reserved)\n\n");
	printf("%-32s  %s", "--mctp_req -i <input_filename> -o <output_filename>\n",
	       "\tSend the request on MCTP protocol\n\n");
	printf("%-32s  %s", "--get_jtag_id\n", "\tGet the JTAG ID Code\n\n");
	printf("%-32s  %s", "--get_device_identity -o <output_filename>\n", "\tGet the Device Identity\n\n");
	printf("%-32s  %s", "--qspi_open\n", "\tOpen the QSPI interface\n\n");
	printf("%-32s  %s", "--qspi_close\n", "\tClose the QSPI interface\n\n");
	printf("%-32s  %s", "--qspi_chipsel <sel>\n", "\tSelect the QSPI chip\n\n");
	printf("%-32s  %s", "--qspi_read --addr <qspi_addr> --len <len in words> -o <output_filename>\n", "\tRead the QSPI data\n\n");
	printf("%-32s  %s",
	       "--qspi_write --addr <qspi_addr> -i <input_filename>\n",
	       "\tWrite the QSPI data\n\n");
	printf("%-32s  %s",
	       "--qspi_erase --addr <qspi_addr> --len <len in multiple of 0x400 words>\n",
	       "\tErase the QSPI data\n\n");
	printf("%-32s  %s", "-v|--verbose",
	       "Verbose Level: log_err, log_wrn, log_inf, log_dbg, log_off\n\n");
	printf("%-32s  %s", "-h|--help", "Show usage message\n");
	printf("\n");
}

/**
 * @brief Write buffer data to file
 *
 * @param filename Name of the file
 * @param buf Buffer holding data
 * @param size Bytes to write to file
 *
 * @return 0 on success, or error on failure
 */
static int store_buffer_to_file(const FCS_OSAL_CHAR *const filename,
				FCS_OSAL_CHAR *buf, const FCS_OSAL_INT size)
{
	FILE *file = fopen(filename, "wb");

	if (!file)
		return -EINVAL;

	FCS_OSAL_INT written = fwrite(buf, 1, size, file);

	if (written != size) {
		fclose(file);
		return -ENOENT;
	}

	fclose(file);
	return 0;
}

/**
 * @brief Get the size of file
 *
 * @param filename Name of file
 *
 * @return returns the size of the file, 0 file empty or file does not exist
 */
static int
get_buffer_size_from_file(const FCS_OSAL_CHAR *const filename)
{
	struct stat st;

	if (stat(filename, &st) != 0) {
		fprintf(stderr, "Unable to open file %s:  %s\n", filename,
		       strerror(errno));
		return -ENOENT;
	}

	return st.st_size;
}

/**
 * @brief Read file and save contents to buffer
 *
 * @param filename Name of the file
 * @param buf Buffer to hold file content
 *
 * @return Returns 0 on success, otherwise error
 */
static int load_buffer_from_file(const FCS_OSAL_CHAR *const filename,
				 FCS_OSAL_CHAR *buf)
{
	struct stat st;

	FILE *file = fopen(filename, "rb");

	if (!file)
		return -EINVAL;

	if (stat(filename, &st) != 0) {
		fclose(file);
		return -ENOENT;
	}

	size_t size = st.st_size;

	if (size == 0) {
		fclose(file);
		return -EINVAL;
	}

	size_t read = fread(buf, 1, size, file);

	if (read != size) {
		fclose(file);
		return -ENOENT;
	}

	fclose(file);
	return 0;
}

/**
 * @brief Convert numerical or hexadecimal string to long.
 *
 * @param str Pointer to string to be converted to long value.
 *
 * @return Value in long
 */
static long convert_string_to_long(char *str)
{
	long value;
	char *endptr;

	/** base is set to zero because the actual base
	 * is determined by the format of the string (e.g., "0x" for
	 * hexadecimal).
	 */
	value = strtol(str, &endptr, 0);
	if (*endptr) {
		fprintf(stderr, "Arg:%s  %s\n", str, strerror(errno));
		fprintf(stderr, "Arg is not numeric or hexadecimal character");
		return -1;
	}
	return value;
}

/**
 * @brief Converts a string representation of a UUID into its
 * corresponding UUID object
 *
 * @param uuid_str Sesesion UUID in string format
 * @param uuid Uuid_t format
 *
 * @return Returns 0 on success, -1 on error
 */
static int string_to_uuid(const char *uuid_str, struct uuid_t *uuid)
{
	int ret = sscanf(uuid_str,
		"%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
		&uuid->time_low, &uuid->time_mid, &uuid->time_hi_and_version,
		&uuid->clock_seq_hi_and_reserved, &uuid->clock_seq_low,
		&uuid->node[0], &uuid->node[1], &uuid->node[2], &uuid->node[3],
		&uuid->node[4], &uuid->node[5]);
	return ret == 11 ? 0 : -1; // Return 0 on success, -1 on failure
}

/**
 * @brief Converts a given UUID (Universally Unique Identifier) to its
 * string representation
 *
 * @param uuid Pointer to UUID
 * @param uuid_str String representation
 */
static void uuid_to_string(const struct uuid_t *uuid, char *uuid_str)
{
	sprintf(uuid_str, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid->time_low, uuid->time_mid, uuid->time_hi_and_version,
		uuid->clock_seq_hi_and_reserved, uuid->clock_seq_low,
		uuid->node[0], uuid->node[1], uuid->node[2], uuid->node[3],
		uuid->node[4], uuid->node[5]);
}

/**
 * @brief Dump the hash bytes
 *
 * @param buf Buffer holding hash bytes
 * @param size Number of bytes to print
 */
static FCS_OSAL_VOID dump_hash(const FCS_OSAL_U8 *const buf,
			       const FCS_OSAL_INT size)
{
	FCS_OSAL_INT i, j;

	for (j = 0; j < size; j += 8) {
		printf("%04x: ", j);
		for (i = 0; i < 8; i++)
			printf("%02x ", buf[j + i]);
		printf("\n");
	}
}

/**
 * @brief Print the passed in hash data.
 *
 * @param gpd Input pointer to the data to be parsed.
 * @param pcntrs Since parsing how many Hash arrays, return pointer to
 * where the counters data should start.
 *
 * @return Return: 0 on success, or error on failure
 */
static int print_hash_data(struct fcs_get_provision_data *gpd,
			   struct fcs_get_counters_keyslots_data **pcntrs)
{
	FCS_OSAL_U8 *p_hash;
	FCS_OSAL_U32 *p_cancel_status;
	FCS_OSAL_INT i;
	FCS_OSAL_INT number_of_hashes;
	FCS_OSAL_INT hash_sz;

	number_of_hashes = gpd->header.num_hashes + 1;
	printf("number of hashes is %d\n", number_of_hashes);

	for (i = 0; i < number_of_hashes; i++) {
		if (gpd->header.type_hash == INTEL_FCS_HASH_SECP256) {
			hash_sz = sizeof(gpd->hash.hash_256->owner_root_hash);
			p_hash = &gpd->hash.hash_256[i].owner_root_hash[0];
			p_cancel_status = &gpd->hash.hash_256[i].cancel_status;
		} else if (gpd->header.type_hash == INTEL_FCS_HASH_SECP384R1) {
			hash_sz = sizeof(gpd->hash.hash_384->owner_root_hash);
			p_hash = &gpd->hash.hash_384[i].owner_root_hash[0];
			p_cancel_status = &gpd->hash.hash_384[i].cancel_status;
		} else {
			return -1;
		}

		dump_hash(p_hash, hash_sz);

		printf("KCS[%d]: 0x%X\n", i, *p_cancel_status);
	}
	/* Set the counter pointer to the end of data */
	if (gpd->header.type_hash == INTEL_FCS_HASH_SECP256)
		*pcntrs = (struct fcs_get_counters_keyslots_data *)
			&gpd->hash.hash_256[number_of_hashes];
	else if (gpd->header.type_hash == INTEL_FCS_HASH_SECP384R1)
		*pcntrs = (struct fcs_get_counters_keyslots_data *)
			&gpd->hash.hash_384[number_of_hashes];

	return 0;
}

/**
 * @brief Prints the provisioned data
 *
 * @param buff buffer containing provision data structure
 */
static FCS_OSAL_VOID print_provision_data(FCS_OSAL_CHAR *buff)
{
	struct fcs_get_provision_data *provision =
		(struct fcs_get_provision_data *)buff;
	struct fcs_get_provision_header *hdr =
		(struct fcs_get_provision_header *)buff;
	struct fcs_get_counters_keyslots_data *pcntrs = NULL;
	static const char no_hash_str[] = "None";
	static const char type256_hash_str[] = "secp256r1";
	static const char type384_hash_str[] = "secp384r1";
	int number_hashes = hdr->num_hashes + 1;
	static const char *type_hash_str = no_hash_str;

	printf("W0:Provision Status Code: 0x%X\n", hdr->provision_status);
	printf("W1:Key Cancellation Status: 0x%X\n", hdr->intel_key_status);
	printf("W2:Co-Sign Status:          %d\n", hdr->co_sign_status);
	printf("W2:RootHash0 Cancel Status: %d\n", hdr->root_hash_status & 0x1);
	printf("W2:RootHash1 Cancel Status: %d\n", hdr->root_hash_status & 0x2);
	printf("W2:RootHash2 Cancel Status: %d\n", hdr->root_hash_status & 0x4);
	printf("W2:Number of Hashes:        %d\n", number_hashes);
	if (hdr->type_hash == INTEL_FCS_HASH_SECP256)
		type_hash_str = type256_hash_str;
	else if (hdr->type_hash == INTEL_FCS_HASH_SECP384R1)
		type_hash_str = type384_hash_str;

	printf("W2:Type of Hash:            %s\n", type_hash_str);
	/* Print the hash data */
	print_hash_data(provision, &pcntrs);
	/* Print the counters here - variable */
	if (pcntrs) {
		printf("C1:Big Counter Base:   0x%X\n",
		       pcntrs->big_cntr_base_value);
		printf("C1:Big Counter Value:  0x%X\n",
		       pcntrs->big_cntr_count_value);
		printf("C2:SVN Counter Value3: 0x%X\n", pcntrs->svn_count_val3);
		printf("C2:SVN Counter Value2: 0x%X\n", pcntrs->svn_count_val2);
		printf("C2:SVN Counter Value1: 0x%X\n", pcntrs->svn_count_val1);
		printf("C2:SVN Counter Value0: 0x%X\n", pcntrs->svn_count_val0);
		/* Match with SDM SPEC1.5 */
		printf("eFuse Service Root Key #0 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot0);
		printf("eFuse Service Root Key #1 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot1);
		printf("eFuse Service Root Key #2 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot2);
		printf("eFuse Service Root Key #3 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot3);
		printf("eFuse Service Root Key #4 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot4);
		printf("eFuse Service Root Key #5 Fuse Status: 0x%X\n",
		       pcntrs->efuse_ifp_key_slot5);

		printf("flash Service Root Key #0 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot0);
		printf("flash Service Root Key #1 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot1);
		printf("flash Service Root Key #2 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot2);
		printf("flash Service Root Key #3 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot3);
		printf("flash Service Root Key #4 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot4);
		printf("flash Service Root Key #5 Fuse Status: 0x%X\n",
		       pcntrs->flash_ifp_key_slot5);

		printf("(Flash Protection Monotonic Counter Status: 0x%X\n",
		       pcntrs->fpm_ctr_counter);
	}
}

/**
 * @brief Displays the session UUID.
 *
 * This function is used to display the session UUID.
 *
 * @param session_uuid Pointer to the session UUID.
 */
static FCS_OSAL_VOID show_session_uuid(FCS_OSAL_UUID *session_uuid)
{
	/* UUID string length + null terminator*/
	char uuid_str[37];

	uuid_to_string((struct uuid_t *)session_uuid, uuid_str);
	printf("Crypto service sessionID=%s\n", uuid_str);
}

/**
 * @brief Check if the session ID is valid.
 *
 * This function checks if the session ID is valid.
 *
 * @param session_uuid Pointer to the session UUID.
 *
 * @return 1 If the session ID is zero, 0 otherwise.
 */
static int is_session_id_valid(FCS_OSAL_UUID *session_uuid)
{
	for (unsigned int i = 0; i < FCS_OSAL_UUID_SIZE; i++) {
		if (session_uuid[i] != 0)
			return 0;
	}
	return -EINVAL;
}

/**
 * @brief Dump the SDOS Header
 *
 * @param AES Header to dump
 */
static void dump_sdos_hdr(struct fcs_aes_crypt_header *sdos_hdr)
{
	FCS_OSAL_UINT i;

	printf("Magic Number: 0x%X\n", sdos_hdr->magic_number);
	printf("Data Length (w/ padding): %d\n", sdos_hdr->data_len);
	printf("Pad: %d\n", sdos_hdr->pad);
	printf("SRKI: %d\n", sdos_hdr->srk_indx);
	printf("ASOI: %d\n", sdos_hdr->app_spec_obj_info);
	printf("Owner ID: ");
	for (i = 0; i < sizeof(sdos_hdr->owner_id); i++)
		printf("%02x ", sdos_hdr->owner_id[i]);

	printf("\n");
	printf("Header Padding: 0x%X\n", sdos_hdr->hdr_pad);
	printf("IV field: ");
	for (i = 0; i < sizeof(sdos_hdr->iv_field); i++)
		printf("%02x ", sdos_hdr->iv_field[i]);
	printf("\n");
}

int main(int argc, char *argv[])
{
	FCS_OSAL_INT ret = 0, c, index, test = -1;
	FCS_OSAL_INT keyid = -1;
	FCS_OSAL_INT context_id = 0, size = 0, src_len = 0, iv_len = 0,
		     aad_len = 0, file_size = 0;
	FCS_OSAL_CHAR status = FCS_GENERIC_ERR;
	FCS_OSAL_CHAR *filename_list = NULL;
	FCS_OSAL_UUID session_uuid[FCS_OSAL_UUID_SIZE];
	FCS_OSAL_CHAR imp_resp[FCS_OSAL_MAX_RESP_STATUS_SIZE];
	FCS_OSAL_UINT imp_resp_len = FCS_OSAL_MAX_RESP_STATUS_SIZE;
	enum fcs_command_code command = FCS_DEV_COMMAND_NONE;
	FCS_OSAL_CHAR log_level[8] = {0};
	FCS_OSAL_U32 set_loglevel;
	FCS_OSAL_CHAR *signature = NULL, *pubkey = NULL;
	FCS_OSAL_U32 signature_len = 0, pubkey_len = 0;
	FCS_OSAL_CHAR *src = NULL, *dst = NULL, *iv = NULL, *aad = NULL;
	FCS_OSAL_UINT export_keylen, keyinfo_len, dst_len = 0, tag_len = 16,
						  tag_count = 1, tag = 3;
	FCS_OSAL_CHAR *filename = NULL, *outfilename = NULL, *iv_file = NULL,
		      *aad_file = NULL;
	FCS_OSAL_CHAR prnt = 0;
	FCS_OSAL_U32 c_size = 0;
	FCS_OSAL_CHAR c_type = 0;
	FCS_OSAL_U32 c_value = 0xFFFFFFFF, cert_size;
	FCS_OSAL_U32 cert_status = FCS_CERT_STATUS_NONE;
	FCS_OSAL_INT cert_request = -1;
	FCS_OSAL_INT step_type = 0;
	FCS_OSAL_U32 chip_id_lo, chip_id_hi;
	FCS_OSAL_INT mac_mode = 0;
	FCS_OSAL_INT sha_op_mode = 0;
	FCS_OSAL_CHAR *file_name[3];
	FCS_OSAL_INT file_index = 0;
	FCS_OSAL_INT input_sz0, input_sz1, input_sz;
	FCS_OSAL_U32 out_sz = 32;
	FCS_OSAL_U16 id = 0;
	FCS_OSAL_U64 own = 0;
	FCS_OSAL_CHAR *endptr;
	FCS_OSAL_BOOL verbose = false;
	FCS_OSAL_INT calc, pad = 0;
	FCS_OSAL_U32 op_mode = 1;
	struct fcs_aes_crypt_header *sdos_hdr;	FCS_OSAL_U32 jtag_id;
	FCS_OSAL_U32 device_identity_len;
	FCS_OSAL_U32 sel = 0xffffffff, qspi_txn_size = 0, qspi_addr = 0;
	FCS_OSAL_CHAR *info;
	FCS_OSAL_U32 info_len;
	FCS_OSAL_CHAR *op_key_obj = NULL;
	FCS_OSAL_U32 op_key_obj_len;
	FCS_OSAL_CHAR *hkdf_resp;
	FCS_OSAL_U32 hkdf_resp_len;
	FCS_OSAL_U32 crypt_mode = 0, block_mode = 0, ecc_curve = 0;
	struct fcs_hkdf_req hkdf;
	struct fcs_ecdsa_verify_req ecdsa_verify_req;
	struct fcs_ecdsa_req ecdsa_req;
	struct fcs_sdos_enc_req sdos_enc_req;
	struct fcs_sdos_dec_req sdos_dec_req;
	struct fcs_digest_get_req get_digest_req;
	struct fcs_mac_verify_req mac_verify_req;
	struct fcs_aes_req aes_req;
	struct fcs_ecdh_req ecdh_req;

	memset(session_uuid, 0, sizeof(session_uuid));

	while ((c = getopt_long(argc, argv, "ephlvxABEDHJKTISMNOPQUWXYZR:t:V:C:G:F:L:y:a:b:f:u:s:i:d:m:n:o:q:r:c:k:w:g:j:z:",
				opts, &index)) != -1) {
		switch (c) {
		case 'A':
			if (command != FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed");
			command = FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD;
			break;

		case 'B':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_IMPORT_KEY_CMD;
			break;

		case 'C':
			if (command != FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed");
			command = FCS_DEV_COUNTER_SET_CMD;
			filename = optarg;
			break;

		case 'D':
			if (command != FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed");
			command = FCS_DEV_DATA_DECRYPTION_CMD;
			break;

		case 'E':
			if (command != FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed");
			command = FCS_DEV_DATA_ENCRYPTION_CMD;
			break;

		case 'F':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			cert_request = convert_string_to_long(optarg);
			command = FCS_DEV_ATTESTATION_GET_CERTIFICATE_CMD;
			filename = optarg;
			break;

		case 'G':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed");
				return -EINVAL;
			}
			command = FCS_DEV_GET_PROVISION_DATA_CMD;
			filename = optarg;
			break;

		case 'H':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_EXPORT_KEY_CMD;
			break;

		case 'I':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CHIP_ID_CMD;
			break;

		case 'J':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_REMOVE_KEY_CMD;
			break;

		case 'K':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_GET_KEY_INFO_CMD;
			break;

		case 'L':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			cert_request = convert_string_to_long(optarg);
			command = FCS_DEV_ATTESTATION_CERTIFICATE_RELOAD_CMD;
			break;

		case 'N':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_GET_DIGEST_CMD;
			break;

		case 'O':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_MAC_VERIFY_CMD;
			break;

		case 'P':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDSA_HASH_SIGNING_CMD;
			break;

		case 'Q':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_SIGNING_CMD;
			break;

		case 'R':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_RANDOM_NUMBER_GEN_CMD;
			filename = optarg;
			break;

		case 'U':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDSA_HASH_VERIFY_CMD;
			break;

		case 'V':
			if (command != FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed");
			command = FCS_DEV_VALIDATE_REQUEST_CMD;
			filename = optarg;
			break;

		case 'W':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_VERIFY_CMD;
			break;

		case 'X':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDH_REQUEST_CMD;
			break;

		case 'Y':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_AES_CRYPT_CMD;
			break;

		case 'Z':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_ECDSA_GET_PUBLIC_KEY_CMD;
			break;

		case 'a':
			if (command != FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			c_value = convert_string_to_long(optarg);
			break;

		case 'b':
			if (command != FCS_DEV_CRYPTO_AES_CRYPT_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			block_mode = convert_string_to_long(optarg);
			break;

		case 'c':
			if (command != FCS_DEV_COUNTER_SET_CMD &&
			    command != FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD)
				printf("Only one command allowed\n");
			test = convert_string_to_long(optarg);
			break;

		case 'd':
			if (command == FCS_DEV_COMMAND_NONE)
				printf("Only one command allowed\n");
			id = convert_string_to_long(optarg);
			break;

		case 'e':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_OPEN_SESSION_CMD;
			break;

		case 'f':
			if (command != FCS_DEV_CRYPTO_AES_CRYPT_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			iv_file = optarg;
			break;

		case 'g':
			sha_op_mode = convert_string_to_long(optarg);
			break;

		case 'h':
			fcs_client_usage();
			break;

		case 'i':
			if (command == FCS_DEV_COMMAND_NONE) {
				printf("Input file needs command");
				return -EINVAL;
			}
			filename = optarg;
			break;

		case 'j':
			size = convert_string_to_long(optarg);
			break;

		case 'k':
			keyid = convert_string_to_long(optarg);
			break;

		case 'l':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_CLOSE_SESSION_CMD;
			break;

		case 'm':
			if (command != FCS_DEV_CRYPTO_AES_CRYPT_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			crypt_mode = convert_string_to_long(optarg);
			break;

		case 'n':
			context_id = convert_string_to_long(optarg);
			if (context_id < 0) {
				printf("Invalid context ID\n");
				return -EINVAL;
			}
			break;

		case 'o':
			if (command == FCS_DEV_COMMAND_NONE) {
				printf("Outfile needs command");
				return -EINVAL;
			}
			outfilename = optarg;
			break;

		case 'p':
			if (command != FCS_DEV_GET_PROVISION_DATA_CMD) {
				printf("Print not valid with this command");
				return -EINVAL;
			}
			prnt = 1;
			break;

		case 'q':
			ecc_curve = convert_string_to_long(optarg);
			break;

		case 'r':
			if (command == FCS_DEV_COMMAND_NONE)
				printf("Owner Hash needs command");
			own = strtoull(optarg, &endptr, 0);
			if (*endptr)
				printf("Owner ID conversion error");
			break;

		case 's':
			if (!optarg) {
				printf("Missing session UUID\n");
				return -EINVAL;
			}

			string_to_uuid(optarg, (struct uuid_t *)session_uuid);
			break;

		case 'u':
			if (command != FCS_DEV_CRYPTO_AES_CRYPT_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			aad_file = optarg;
			break;

		case 'v':
			if (command == FCS_DEV_COMMAND_NONE) {
				printf("One command is expected\n");
				return -EINVAL;
			}

			verbose = true;
			break;

		case 'x':
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_CREATE_KEY_CMD;
			break;

		case 'y':
			if (command != FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			c_type = convert_string_to_long(optarg);
			break;

		case 'z':
			filename_list = optarg;
			break;

		case 4:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			command = FCS_DEV_CRYPTO_HKDF_REQUEST_CMD;
			break;

		case 5:
			if (command != FCS_DEV_CRYPTO_HKDF_REQUEST_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			step_type = convert_string_to_long(optarg);
			break;

		case 6:
			if (command != FCS_DEV_CRYPTO_HKDF_REQUEST_CMD) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}
			mac_mode = convert_string_to_long(optarg);
			break;

		case 7:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_MCTP_REQUEST_CMD;
			break;

		case 8:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_GET_JTAG_ID_CMD;
			break;

		case 9:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_GET_DEVICE_IDENTITY_CMD;
			break;

		case 10:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_QSPI_OPEN_CMD;
			break;

		case 11:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_QSPI_CLOSE_CMD;
			break;

		case 12:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			sel = convert_string_to_long(optarg);

			command = FCS_DEV_CRYPTO_QSPI_CS_CMD;
			break;

		case 13:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_QSPI_READ_CMD;
			break;

		case 14:
			if (command != FCS_DEV_CRYPTO_QSPI_READ_CMD &&
			    command != FCS_DEV_CRYPTO_QSPI_WRITE_CMD &&
			    command != FCS_DEV_CRYPTO_QSPI_ERASE_CMD) {
				printf("Not valid option for this command\n");
				return -EINVAL;
			}

			qspi_addr = convert_string_to_long(optarg);
			break;

		case 15:
			if (command != FCS_DEV_CRYPTO_QSPI_READ_CMD &&
			    command != FCS_DEV_CRYPTO_QSPI_WRITE_CMD &&
			    command != FCS_DEV_CRYPTO_QSPI_ERASE_CMD) {
				printf("Not valid option for this command\n");
				return -EINVAL;
			}

			qspi_txn_size = convert_string_to_long(optarg);
			break;

		case 16:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Only one command allowed\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_QSPI_WRITE_CMD;
			break;

		case 17:
			if (command != FCS_DEV_COMMAND_NONE) {
				printf("Not valid option for this command\n");
				return -EINVAL;
			}

			command = FCS_DEV_CRYPTO_QSPI_ERASE_CMD;
			break;

		case 18:
			if (command != FCS_DEV_CRYPTO_HKDF_REQUEST_CMD) {
				printf("This option is allowed only for hdkf request\n");
				return -EINVAL;
			}

			op_key_obj = optarg;
			break;

		case 19:
			set_loglevel = convert_string_to_long(optarg);

			if (set_loglevel == 0)
				snprintf(log_level, sizeof(log_level),
					 "log_off");
			else if (set_loglevel == 1)
				snprintf(log_level, sizeof(log_level),
					 "log_err");
			else if (set_loglevel == 2)
				snprintf(log_level, sizeof(log_level),
					 "log_wrn");
			else if (set_loglevel == 3)
				snprintf(log_level, sizeof(log_level),
					 "log_inf");
			else if (set_loglevel == 4)
				snprintf(log_level, sizeof(log_level),
					 "log_dbg");
			else {
				printf("Invalid loglevel, setting default log level: log_inf");
				snprintf(log_level, sizeof(log_level),
					 "log_inf");
			}
			break;

		default:
			fcs_client_usage();
			return -EINVAL;
		}
	}

	/** Initialize the FCS library */
	ret = libfcs_init(log_level);
	if (ret != 0) {
		printf("Failed to initialize FCS library: %d\n", ret);
		return ret;
	}

	switch (command) {
	case FCS_DEV_CRYPTO_OPEN_SESSION_CMD:
		ret = fcs_open_service_session(session_uuid);
		if (ret != 0)
			return ret;

		show_session_uuid(session_uuid);
		break;

	case FCS_DEV_CRYPTO_CLOSE_SESSION_CMD:
		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID is invalid\n");
			return -EINVAL;
		}

		ret = fcs_close_service_session(session_uuid);
		if (ret != 0)
			return ret;
		break;

	case FCS_DEV_RANDOM_NUMBER_GEN_CMD:
		if (!filename) {
			fprintf(stderr, "Missing filename to save data into\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)calloc(size, sizeof(FCS_OSAL_CHAR));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s: %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = fcs_random_number_ext(session_uuid, context_id, dst,
					    size);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(filename, dst, size);
		if (ret < 0) {
			fprintf(stderr, "Failed to store random number to file: %d\n",
				ret);
			free(dst);
			return ret;
		}

		free(dst);
		break;

	case FCS_DEV_CRYPTO_IMPORT_KEY_CMD:
		if (!filename) {
			fprintf(stderr, "Missing filename to save data into\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID is invalid\n");
			return -EINVAL;
		}

		size = get_buffer_size_from_file(filename);
		if (size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (size < 0) {
			return size;
		}

		/* Allocate memory to read key from file */
		src = (FCS_OSAL_CHAR *)calloc(size, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load key object from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		ret = fcs_import_service_key(session_uuid, src, size, imp_resp,
					     &imp_resp_len);
		if (ret) {
			free(src);
			return ret;
		}

		free(src);
		break;

	case FCS_DEV_CRYPTO_EXPORT_KEY_CMD:
		if (!outfilename) {
			fprintf(stderr, "Missing key object filename to save data into\n");
			return -EINVAL;
		}

		if (keyid < 0) {
			fprintf(stderr, "Invalid key id\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)calloc(CRYPTO_EXPORTED_KEY_OBJECT_MAX_SZ,
					     sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			return -ENOMEM;
		}

		ret = fcs_export_service_key(session_uuid, keyid, dst,
					     &export_keylen);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, export_keylen);
		if (ret < 0) {
			fprintf(stderr, "Failed to export key object to file: %s. ret:%d\n",
				outfilename, ret);
			free(dst);
			return ret;
		}

		free(dst);
		break;

	case FCS_DEV_CRYPTO_REMOVE_KEY_CMD:

		if (keyid < 0) {
			fprintf(stderr, "Invalid key id\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		ret = fcs_remove_service_key(session_uuid, keyid);
		if (ret)
			return ret;
		break;

	case FCS_DEV_CRYPTO_GET_KEY_INFO_CMD:
		keyinfo_len = CRYPTO_GET_KEY_INFO_MAX_SZ;

		if (!outfilename) {
			fprintf(stderr, "Missing filename to save data into\n");
			return -EINVAL;
		}

		if (keyid < 0) {
			fprintf(stderr, "Invalid key id\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)calloc(keyinfo_len, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = fcs_get_service_key_info(session_uuid, keyid, dst,
					       &keyinfo_len);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, keyinfo_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to get key info to file: %d\n",
				ret);
			free(dst);
			return ret;
		}

		memset(dst, 0, CRYPTO_GET_KEY_INFO_MAX_SZ);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_CREATE_KEY_CMD:
		if (!filename || !outfilename) {
			fprintf(stderr, "Missing key object filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		size = get_buffer_size_from_file(filename);
		if (size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (size < 0) {
			return size;
		}

		/* Allocate memory to read key from file */
		src = (FCS_OSAL_CHAR *)malloc(size);
		if (!src) {
			fprintf(stderr, "Failed to allocate memory for create key\n");
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load key object from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		ret = fcs_create_service_key(session_uuid, src, size, &status,
					     sizeof(status));
		if (ret) {
			free(src);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, &status,
					   sizeof(status));
		if (ret < 0) {
			fprintf(stderr, "Failed to store create key status to file: %d\n",
				ret);
			free(src);
			return ret;
		}

		free(src);
		break;

	case FCS_DEV_CRYPTO_HKDF_REQUEST_CMD:
		if (!filename_list || !op_key_obj) {
			fprintf(stderr, "Missing input file list or output key object\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		file_name[0] = strtok(filename_list, "#");
		file_index = 1;
		while (file_index < 3) {
			file_name[file_index] = strtok(NULL, "#");
			if (!file_name[file_index])
				break;
			file_index++;
		}

		/* input 1 len */
		src_len = get_buffer_size_from_file(file_name[0]);
		if (src_len == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[0]);
			return -EINVAL;
		} else if (src_len < 0) {
			return src_len;
		}

		/* input 1 buffer */
		src = (FCS_OSAL_CHAR *)malloc(src_len * sizeof(FCS_OSAL_CHAR));
		if (!src) {
			fprintf(stderr, "Failed to allocate memory for hkdf request\n");
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[0], src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %s err:%d\n",
				file_name[0], ret);
			free(src);
			return ret;
		}

		/* input 2 len */
		file_size = get_buffer_size_from_file(file_name[1]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[1]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		info_len = file_size;

		/* input 2 buffer */
		info = (FCS_OSAL_CHAR *)malloc(info_len *
					       sizeof(FCS_OSAL_CHAR));
		if (!info) {
			fprintf(stderr, "Failed to allocate memory for hkdf info\n");
			free(src);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[1], info);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %s err:%d\n",
				file_name[1], ret);
			free(src);
			free(info);
			return ret;
		}

		file_size = get_buffer_size_from_file(file_name[2]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[2]);
			free(src);
			free(info);
			return -EINVAL;
		} else if (file_size < 0) {
			free(src);
			free(info);
			return file_size;
		}

		op_key_obj_len = file_size;

		op_key_obj = (FCS_OSAL_CHAR *)malloc(op_key_obj_len *
						     sizeof(FCS_OSAL_CHAR));
		if (!op_key_obj) {
			fprintf(stderr, "Failed to allocate memory for hkdf output key object\n");
			free(src);
			free(info);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[2], op_key_obj);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %s err:%d\n",
				file_name[2], ret);
			free(src);
			free(info);
			free(op_key_obj);
			return ret;
		}

		hkdf_resp_len = CRYPTO_HKDF_RESPONSE_MAX_SZ;

		hkdf_resp = (FCS_OSAL_CHAR *)malloc(hkdf_resp_len);
		if (!hkdf_resp) {
			fprintf(stderr, "Failed to allocate memory for hkdf response\n");
			free(src);
			free(info);
			free(op_key_obj);
			return -ENOMEM;
		}

		hkdf.step_type = step_type;
		hkdf.mac_mode = mac_mode;
		hkdf.input1 = src;
		hkdf.input1_len = (FCS_OSAL_U32)src_len;
		hkdf.input2 = info;
		hkdf.input2_len = info_len;
		hkdf.output_key_obj = op_key_obj;
		hkdf.output_key_obj_len = op_key_obj_len;
		hkdf.hkdf_resp = hkdf_resp;
		hkdf.hkdf_resp_len = &hkdf_resp_len;

		ret = fcs_hkdf_request(session_uuid, keyid, &hkdf);
		if (ret) {
			free(src);
			free(info);
			free(op_key_obj);
			free(hkdf_resp);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store kdk to file: %d\n",
				ret);
			free(src);
			free(info);
			free(op_key_obj);
			free(hkdf_resp);
			return ret;
		}

		free(src);
		free(info);
		free(op_key_obj);
		free(hkdf_resp);
		break;

	case FCS_DEV_GET_PROVISION_DATA_CMD:
		if (!filename)
			fprintf(stderr, "Missing filename to save Provision Data\n");

		dst = malloc(sizeof(struct fcs_get_provision_data));
		if (!dst) {
			fprintf(stderr, "can't malloc buffer for provision data:  %s\n",
				strerror(errno));
			return -ENOMEM;
		}

		c_size = sizeof(struct fcs_get_provision_data);
		ret = fcs_service_get_provision_data(dst, &c_size);
		if (ret) {
			free(dst);
			return ret;
		}

		if (prnt == 1)
			print_provision_data(dst);

		ret = store_buffer_to_file(filename, dst, c_size);
		if (ret < 0) {
			fprintf(stderr, "Failed to store provision data to file. Error: %d\n",
				ret);
			free(dst);
			return ret;
		}

		memset(dst, 0, sizeof(struct fcs_get_provision_data));
		free(dst);
		break;

	case FCS_DEV_COUNTER_SET_CMD:
		if (!filename) {
			fprintf(stderr, "Missing filename with Counter Set Data\n");
			return -EINVAL;
		}

		if (test != 0 && test != 1) {
			fprintf(stderr, "Error with test bit - must be 0 or 1\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		size = file_size;

		src = (FCS_OSAL_CHAR *)calloc(size, sizeof(FCS_OSAL_CHAR));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		ret = fcs_service_counter_set(src, size, test,
					      (FCS_OSAL_CHAR *)&cert_status);
		if (ret) {
			free(src);
			return ret;
		}

		if (ret == MBOX_RESP_INVALID_CERTIFICATE ||
		    ret == MBOX_RESP_AUTHENTICATION_FAIL)
			cert_status = AUTHENTICATION_FAILED;
		else if (ret == NOT_ALLOWED_UNDER_SECURITY_SETTINGS)
			cert_status = DEV_NOT_OWNED;

		if (ret) {
			fprintf(stderr, "Certificate Error: 0x%X\n",
				cert_status);
			free(src);
			return ret;
		}

		free(src);
		break;

	case FCS_DEV_COUNTER_SET_PREAUTHORIZED_CMD:
		/* check counter value is in valid range */
		if (!c_type || c_type > 5) {
			fprintf(stderr, "Invalid Counter type parameter (Must be 1 to 5)\n");
			return -EINVAL;
		}
		if (c_type > 1 && c_value > 64) {
			fprintf(stderr, "Invalid Counter Value parameter (Counter value must be from 0 to 64)\n");
			return -EINVAL;
		}
		if (c_type == 1 && c_value > 495) {
			fprintf(stderr, "Invalid Big Counter parameter (Counter value must be from 0 to 495)\n");
			return -EINVAL;
		}

		ret = fcs_service_counter_set_preauthorized(c_type, c_value,
							    test);
		if (ret != 0)
			return ret;
		break;

	case FCS_DEV_CRYPTO_AES_CRYPT_CMD:
		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename\n");
			return -EINVAL;
		}

		if (block_mode != 0 && !iv_file) {
			fprintf(stderr, "NULL iv_field:  %s\n",
				strerror(errno));
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		/* Allocate memory to read input data from file */
		src = (FCS_OSAL_CHAR *)malloc(src_len);
		if (!src) {
			fprintf(stderr, "can't malloc buffer for input %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			free(src);
			fprintf(stderr, "Failed to load input data from file: %d\n",
				ret);
			return ret;
		}
		if (block_mode != 0) {
			file_size = get_buffer_size_from_file(iv_file);
			if (file_size == 0) {
				fprintf(stderr, "File: %s empty\n", iv_file);
				free(src);
				return -EINVAL;
			} else if (file_size < 0) {
				free(src);
				return file_size;
			}

			iv_len = file_size;

			/* Allocate memory to read iv from file */
			iv = (FCS_OSAL_CHAR *)malloc(iv_len);
			if (!iv) {
				fprintf(stderr, "Failed to allocate memory for iv buffer\n");
				free(src);
				return -ENOMEM;
			}

			ret = load_buffer_from_file(iv_file, iv);
			if (ret < 0) {
				fprintf(stderr, "Failed to load iv from file: %d\n",
					ret);
				free(src);
				free(iv);
				return ret;
			}
		}

		if (block_mode == FCS_AES_BLOCK_MODE_GCM ||
		    block_mode == FCS_AES_BLOCK_MODE_GHASH) {
			if (!aad_file) {
				fprintf(stderr, "Missing AAD filename\n");
				if (iv)
					free(iv);
				free(src);
				return -EINVAL;
			}

			file_size = get_buffer_size_from_file(aad_file);
			if (file_size == 0) {
				fprintf(stderr, "File: %s empty\n", aad_file);
				if (iv)
					free(iv);
				free(src);
				return -EINVAL;
			} else if (file_size < 0) {
				if (iv)
					free(iv);
				free(src);
				return file_size;
			}

			aad_len = file_size;

			/* Allocate memory to read iv from file */
			aad = (FCS_OSAL_CHAR *)malloc(aad_len);
			if (!aad) {
				fprintf(stderr, "Failed to allocate memory for aad buffer\n");
				if (iv)
					free(iv);
				free(src);
				return -ENOMEM;
			}

			ret = load_buffer_from_file(aad_file, aad);
			if (ret < 0) {
				fprintf(stderr, "Failed to load aad from file: %d\n",
					ret);
				free(src);
				if (iv)
					free(iv);
				free(aad);
				return ret;
			}
		}

		dst_len =
			(src_len % FCS_AES_CRYPT_BLOCK_SIZE) ?
				(FCS_OSAL_U32)(src_len /
						FCS_AES_CRYPT_BLOCK_SIZE + 1) *
					FCS_AES_CRYPT_BLOCK_SIZE :
				(FCS_OSAL_U32)src_len;
		tag_count = dst_len % (4 * 1024 * 1024) ?
				    (dst_len / (4 * 1024 * 1024) + 1) :
				    dst_len / (4 * 1024 * 1024);
		dst_len += (tag_count * tag_len);
		dst = (FCS_OSAL_CHAR *)malloc(dst_len);
		if (!dst) {
			fprintf(stderr, "Failed to allocate memory for kdk buffer\n");
			free(src);
			if (iv)
				free(iv);
			if (block_mode == FCS_AES_BLOCK_MODE_GCM ||
			    block_mode == FCS_AES_BLOCK_MODE_GHASH)
				free(aad);
			return -ENOMEM;
		}

		memset(dst, 0, dst_len);

		aes_req.crypt_mode = crypt_mode;
		aes_req.block_mode = block_mode;
		aes_req.iv_source = FCS_AES_IV_SOURCE_EXTERNAL;
		aes_req.iv = iv;
		aes_req.iv_len = iv_len;
		aes_req.tag_len = tag;
		aes_req.aad_len = 0;
		aes_req.aad = aad;
		aes_req.input = src;
		aes_req.ip_len = src_len;
		aes_req.output = dst;
		aes_req.op_len = &dst_len;

		ret = fcs_aes_crypt(session_uuid, keyid, context_id, &aes_req);
		if (ret) {
			free(src);
			if (iv)
				free(iv);
			free(dst);
			if (block_mode == FCS_AES_BLOCK_MODE_GCM ||
			    block_mode == FCS_AES_BLOCK_MODE_GHASH)
				free(aad);

			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr,
				"Failed to store AES Crypt to file: %d\n", ret);
			free(src);
			if (iv)
				free(iv);
			free(dst);
			if (block_mode == FCS_AES_BLOCK_MODE_GCM ||
			    block_mode == FCS_AES_BLOCK_MODE_GHASH)
				free(aad);

			return ret;
		}

		free(src);
		if (iv)
			free(iv);
		free(dst);

		if (block_mode == FCS_AES_BLOCK_MODE_GCM ||
		    block_mode == FCS_AES_BLOCK_MODE_GHASH)
			free(aad);
		break;

	case FCS_DEV_CRYPTO_ECDH_REQUEST_CMD:

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		/* Allocate memory to read inputdata from file */
		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load input data from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		dst_len = src_len;

		dst = (FCS_OSAL_CHAR *)calloc(dst_len, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ecdh_req.ecc_curve = ecc_curve;
		ecdh_req.pubkey = src;
		ecdh_req.pubkey_len = src_len;
		ecdh_req.shared_secret = dst;
		ecdh_req.shared_secret_len = &dst_len;
		ret = fcs_ecdh_request(session_uuid, keyid, context_id,
				       &ecdh_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store ECDH request to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_GET_DIGEST_CMD:
		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		/* Allocate memory to read input file */
		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load input file: %d\n", ret);
			free(src);
			return ret;
		}

		dst = (FCS_OSAL_CHAR *)calloc(CRYPTO_DIGEST_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		get_digest_req.sha_op_mode = sha_op_mode;
		get_digest_req.sha_digest_sz = size;
		get_digest_req.src = src;
		get_digest_req.src_len = src_len;
		get_digest_req.digest = dst;
		get_digest_req.digest_len = &dst_len;

		ret = fcs_get_digest(session_uuid, context_id, keyid,
				     &get_digest_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store digest to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_MAC_VERIFY_CMD:
		if (!filename_list || !outfilename) {
			fprintf(stderr, "Missing input file list or output filename");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		/* parse to data and mac binary file */
		file_name[file_index] = strtok(filename_list, "#");
		while (file_name[file_index]) {
			file_index++;
			if (file_index <= 1)
				file_name[file_index] = strtok(NULL, "#");
			else
				break;
		}
		if (file_index != 2) {
			fprintf(stderr,
				"Missing data or mac file in -z option\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(file_name[0]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[0]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		input_sz0 = file_size;

		file_size = get_buffer_size_from_file(file_name[1]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[1]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		input_sz1 = file_size;
		input_sz = input_sz0 + input_sz1;

		src = (FCS_OSAL_CHAR *)malloc(input_sz * sizeof(FCS_OSAL_CHAR));
		if (!src) {
			fprintf(stderr, "can't malloc buffer for %s:  %s\n",
				file_name[0], strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[0], src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		ret = load_buffer_from_file(file_name[1], src + input_sz0);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		dst = (FCS_OSAL_CHAR *)malloc(out_sz);
		if (!dst) {
			fprintf(stderr, "can't malloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		mac_verify_req.op_mode = sha_op_mode;
		mac_verify_req.dig_sz = size;
		mac_verify_req.src = src;
		mac_verify_req.src_sz = input_sz;
		mac_verify_req.dst = dst;
		mac_verify_req.dst_sz = &out_sz;
		mac_verify_req.user_data_sz = input_sz0;

		ret = fcs_mac_verify(session_uuid, context_id, keyid,
				     &mac_verify_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, out_sz);
		if (ret < 0) {
			fprintf(stderr, "Failed to store digest to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CHIP_ID_CMD:
		ret = fcs_get_chip_id(&chip_id_lo, &chip_id_hi);
		if (ret != 0)
			return ret;

		printf("device chipID[low]=0x%08x, chipID[high]=0x%08x\n",
		       chip_id_lo, chip_id_hi);
		break;

	case FCS_DEV_ATTESTATION_GET_CERTIFICATE_CMD:
		if (!outfilename) {
			fprintf(stderr, "Missing output filename\n");
			return -EINVAL;
		}

		if (cert_request < 0) {
			fprintf(stderr, "Invalid certificate request\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)calloc(
			ATTESTATION_CERTIFICATE_RSP_MAX_SZ,
			sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			return -ENOMEM;
		}

		cert_size = ATTESTATION_CERTIFICATE_RSP_MAX_SZ;

		ret = fcs_attestation_get_certificate(cert_request, dst,
						      &cert_size);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, cert_size);
		if (ret < 0) {
			fprintf(stderr, "Failed to store certificate to file: %d\n",
				ret);
			free(dst);
			return ret;
		}

		memset(dst, 0, ATTESTATION_CERTIFICATE_RSP_MAX_SZ);
		free(dst);
		break;

	case FCS_DEV_ATTESTATION_CERTIFICATE_RELOAD_CMD:
		if (cert_request < 0) {
			fprintf(stderr, "Invalid certificate request\n");
			return -EINVAL;
		}

		ret = fcs_attestation_certificate_reload(cert_request);
		if (ret)
			return ret;
		break;

	case FCS_DEV_CRYPTO_MCTP_REQUEST_CMD:
		if (!filename) {
			fprintf(stderr, "Missing input filename\n");
			return -EINVAL;
		}

		if (!outfilename) {
			fprintf(stderr, "Missing output filename\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		src = (FCS_OSAL_CHAR *)malloc(src_len * sizeof(FCS_OSAL_CHAR));
		if (!src) {
			fprintf(stderr, "Failed to allocate memory for MCTP request\n");
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		dst = (FCS_OSAL_CHAR *)malloc(MCTP_RSP_MAX_SZ);
		if (!dst) {
			fprintf(stderr, "Failed to allocate memory for MCTP response\n");
			free(src);
			return -ENOMEM;
		}

		dst_len = MCTP_RSP_MAX_SZ;

		ret = fcs_mctp_cmd_send(src, src_len, dst, &dst_len);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store MCTP response to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_GET_JTAG_ID_CMD:
		ret = fcs_get_jtag_idcode(&jtag_id);
		if (ret)
			return ret;

		printf("JTAG ID: 0x%x\n", jtag_id);

		break;

	case FCS_DEV_CRYPTO_GET_DEVICE_IDENTITY_CMD:
		if (!outfilename) {
			fprintf(stderr, "Missing output filename\n");
			return -EINVAL;
		}

		device_identity_len = DEVICE_IDENTITY_MAX_SZ;

		dst = (FCS_OSAL_CHAR *)malloc(device_identity_len);
		if (!dst) {
			fprintf(stderr, "Failed to alloc memory for device identity\n");
			return -ENOMEM;
		}

		ret = fcs_get_device_identity(dst, &device_identity_len);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst,
					   device_identity_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store device identity to file: %d\n",
				ret);
			free(dst);
			return ret;
		}

		free(dst);
		break;

	case FCS_DEV_CRYPTO_QSPI_OPEN_CMD:

		ret = fcs_qspi_open();
		if (ret)
			return ret;
		break;

	case FCS_DEV_CRYPTO_QSPI_CLOSE_CMD:

		ret = fcs_qspi_close();
		if (ret)
			return ret;
		break;

	case FCS_DEV_CRYPTO_QSPI_CS_CMD:
		if (sel == 0xffffffff) {
			fprintf(stderr, "Invalid CS selection\n");
			return -EINVAL;
		}

		ret = fcs_qspi_set_cs(sel);
		if (ret)
			return ret;
		break;

	case FCS_DEV_CRYPTO_QSPI_READ_CMD:
		if (!outfilename) {
			fprintf(stderr, "Missing output filename\n");
			return -EINVAL;
		}

		if (qspi_txn_size == 0) {
			fprintf(stderr, "Invalid QSPI transaction size\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)malloc(qspi_txn_size * 4);
		if (!dst) {
			fprintf(stderr, "Failed to allocate memory for QSPI read\n");
			return -ENOMEM;
		}

		ret = fcs_qspi_read(qspi_addr, dst, qspi_txn_size);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, qspi_txn_size * 4);
		if (ret < 0) {
			fprintf(stderr,
				"Failed to store QSPI read to file: %d\n", ret);
			free(dst);
			return ret;
		}

		free(dst);
		break;

	case FCS_DEV_CRYPTO_QSPI_WRITE_CMD:
		if (!filename) {
			fprintf(stderr, "Missing input filename\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		qspi_txn_size = file_size;

		src = (FCS_OSAL_CHAR *)malloc(qspi_txn_size);
		if (!src) {
			fprintf(stderr, "Failed to allocate memory for QSPI write\n");
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		ret = fcs_qspi_write(qspi_addr, src, qspi_txn_size / 4);
		if (ret) {
			free(src);
			return ret;
		}

		free(src);
		break;

	case FCS_DEV_CRYPTO_QSPI_ERASE_CMD:
		if (qspi_txn_size == 0) {
			fprintf(stderr, "Invalid QSPI transaction size\n");
			return -EINVAL;
		}

		ret = fcs_qspi_erase(qspi_addr, qspi_txn_size);
		if (ret)
			return ret;
		break;

	case FCS_DEV_DATA_ENCRYPTION_CMD:
		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		size = file_size;

		if (verbose)
			fprintf(stderr, "%s[%d] filesize=%d\n", __func__,
				__LINE__, size);

		/* Make sure the data is less than 32K - 96 bytes */
		if (size > SDOS_PLAINDATA_MAX_SZ ||
		    size < SDOS_PLAINDATA_MIN_SZ) {
			fprintf(stderr, "Invalid filesize %d Must be > 16 and <= 32,672\n",
				size);
			return -EINVAL;
		}

		/* Allocate memory to read key from file */
		src = (FCS_OSAL_CHAR *)calloc(SDOS_DECRYPTED_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		dst = (FCS_OSAL_CHAR *)calloc(SDOS_ENCRYPTED_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename,
				src + sizeof(struct fcs_aes_crypt_header));
		if (ret < 0) {
			fprintf(stderr, "Failed to load key object from file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		/* Initialize the header */
		sdos_hdr = (struct fcs_aes_crypt_header *)src;
		sdos_hdr->magic_number = SDOS_MAGIC_WORD;
		calc = size % 32;
		if (calc)
			pad = 32 - calc;
		sdos_hdr->data_len = size + pad;
		sdos_hdr->pad = pad;
		sdos_hdr->srk_indx = 0;
		sdos_hdr->app_spec_obj_info = id;

		for (FCS_OSAL_UINT i = 0; i < sizeof(sdos_hdr->owner_id); i++) {
			sdos_hdr->owner_id[i] = (uint8_t)own;
			own >>= 8;
		}
		sdos_hdr->hdr_pad = SDOS_HEADER_PADDING;
		/* to initialize for the generated IV */
		for (FCS_OSAL_UINT i = 0; i < sizeof(sdos_hdr->iv_field); i++)
			sdos_hdr->iv_field[i] = 0;

		if (verbose)
			dump_sdos_hdr(sdos_hdr);

		printf("Size of struct fcs_aes_crypt_header: %lu\n",
		       sizeof(struct fcs_aes_crypt_header));

		src_len = size + pad + sizeof(struct fcs_aes_crypt_header);
		dst_len = src_len + SDOS_HMAC_SZ;

		sdos_enc_req.op_mode = op_mode;
		sdos_enc_req.own = own;
		sdos_enc_req.id = id;
		sdos_enc_req.src = src;
		sdos_enc_req.src_sz = src_len;
		sdos_enc_req.dst = dst;
		sdos_enc_req.dst_sz = &dst_len;

		ret = fcs_sdos_encrypt(session_uuid, context_id, &sdos_enc_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		if (verbose) {
			printf("Save encrypted data to %s\n", outfilename);
			printf("Saving %d [0x%X] bytes\n", dst_len, dst_len);
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store encrypted data to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		memset(src, 0, SDOS_DECRYPTED_MAX_SZ);
		memset(dst, 0, SDOS_ENCRYPTED_MAX_SZ);
		free(src);
		free(dst);
		break;

	case FCS_DEV_DATA_DECRYPTION_CMD:
		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input file list or output filename");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		size = file_size;
		calc = size % 16;
		if (calc)
			pad = 16 - calc;

		if (verbose)
			printf("%s[%d] filesize=%d\n", __func__, __LINE__,
			       size);

		/* Make sure the data (header + payload) is within the range  */
		if (size > SDOS_ENCRYPTED_MAX_SZ ||
		    size < SDOS_ENCRYPTED_MIN_SZ) {
			fprintf(stderr, "Inval filesize %d Must be >= 120 & <= 32,760\n",
				size);
			return -EINVAL;
		}

		/* Allocate memory to read key from file */
		src = (FCS_OSAL_CHAR *)calloc(SDOS_ENCRYPTED_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		dst = (FCS_OSAL_CHAR *)calloc(SDOS_DECRYPTED_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load key object from file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		op_mode = 0;
		dst_len = size + pad;
		sdos_dec_req.op_mode = op_mode;
		sdos_dec_req.src = src;
		sdos_dec_req.src_sz = size;
		sdos_dec_req.pad = pad;
		sdos_dec_req.dst = dst;
		sdos_dec_req.dst_sz = &dst_len;

		ret = fcs_sdos_decrypt(session_uuid, context_id, &sdos_dec_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		sdos_hdr = (struct fcs_aes_crypt_header *)dst;
		if (verbose)
			dump_sdos_hdr(sdos_hdr);

		if (verbose) {
			printf("Save decrypted data to %s\n", outfilename);
			printf("Saving %d [0x%X] bytes\n",
			       (sdos_hdr->data_len - sdos_hdr->pad),
			       (sdos_hdr->data_len - sdos_hdr->pad));
		}

		ret = store_buffer_to_file(outfilename,
			dst + sizeof(struct fcs_aes_crypt_header),
			(sdos_hdr->data_len - sdos_hdr->pad));
		if (ret < 0) {
			fprintf(stderr, "Failed to store encrypted data to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		memset(src, 0, SDOS_ENCRYPTED_MAX_SZ);
		memset(dst, 0, SDOS_DECRYPTED_MAX_SZ);
		free(src);
		free(dst);
		break;

	case  FCS_DEV_CRYPTO_ECDSA_GET_PUBLIC_KEY_CMD:
		if (!outfilename) {
			fprintf(stderr, "Missing output filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		dst = (FCS_OSAL_CHAR *)calloc(ECDSA_PUB_KEY_MAX_SZ,
					      sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			return -ENOMEM;
		}

		dst_len = ECDSA_PUB_KEY_MAX_SZ;

		ret = fcs_ecdsa_get_pub_key(session_uuid, context_id, keyid,
					    ecc_curve, dst, &dst_len);
		if (ret) {
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store ECDSA public key to file: %d\n",
				ret);
			free(dst);
			return ret;
		}

		free(dst);
		break;

	case FCS_DEV_CRYPTO_ECDSA_HASH_SIGNING_CMD:

		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		/* Allocate memory to read inputdata from file */
		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load input data from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		dst_len = ECDSA_SIGNATURE_MAX_SZ;

		dst = (FCS_OSAL_CHAR *)calloc(dst_len, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ecdsa_req.ecc_curve = ecc_curve;
		ecdsa_req.src = src;
		ecdsa_req.src_len = src_len;
		ecdsa_req.dst = dst;
		ecdsa_req.dst_len = &dst_len;

		ret = fcs_ecdsa_hash_sign(session_uuid, context_id, keyid,
					  &ecdsa_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			fprintf(stderr, "Failed to store ECDSA hash sign to file: %d\n",
				ret);
			free(src);
			free(dst);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_ECDSA_HASH_VERIFY_CMD:

		if (!filename_list || !outfilename) {
			fprintf(stderr, "Missing input file list or output filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Missing\n");
			return -EINVAL;
		}

		/* parse to data and signature binary file */
		file_name[file_index] = strtok(filename_list, "#");
		while (file_name[file_index]) {
			file_index++;
			if (file_index <= 2)
				file_name[file_index] = strtok(NULL, "#");
			else
				break;
		}

		if (file_index < 2 || (file_index < 3 && keyid == 0)) {
			fprintf(stderr, "Missing hash data or signature\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(file_name[0]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[0]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		file_size = get_buffer_size_from_file(file_name[1]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[1]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		signature_len = file_size;

		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				file_name[0], strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[0], src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		signature = (FCS_OSAL_CHAR *)calloc(signature_len,
						    sizeof(FCS_OSAL_U8));
		if (!signature) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				file_name[1], strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[1], signature);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n",
				ret);
			free(src);
			free(signature);
			return ret;
		}

		dst = (FCS_OSAL_CHAR *)calloc(out_sz, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			free(signature);
			return -ENOMEM;
		}

		if (keyid == 0) {
			file_size = get_buffer_size_from_file(file_name[2]);
			if (file_size == 0) {
				fprintf(stderr, "File: %s empty\n",
					file_name[2]);
				free(src);
				free(dst);
				free(signature);
				return -EINVAL;
			} else if (file_size < 0) {
				free(src);
				free(dst);
				free(signature);
				return file_size;
			}

			pubkey_len = file_size;
			pubkey = (FCS_OSAL_CHAR *)calloc(pubkey_len,
							 sizeof(FCS_OSAL_CHAR));
			if (!pubkey) {
				fprintf(stderr, "can't calloc buffer for %s:  %s\n",
					file_name[2], strerror(errno));
				free(src);
				free(dst);
				free(signature);
				return -ENOMEM;
			}

			ret = load_buffer_from_file(file_name[2], pubkey);
			if (ret < 0) {
				fprintf(stderr, "Failed to load buffer from file: %d\n",
					ret);
				free(src);
				free(dst);
				free(signature);
				free(pubkey);
				return ret;
			}
		}

		ecdsa_verify_req.ecc_curve = ecc_curve;
		ecdsa_verify_req.src = src;
		ecdsa_verify_req.src_len = src_len;
		ecdsa_verify_req.signature = signature;
		ecdsa_verify_req.signature_len = signature_len;
		ecdsa_verify_req.pubkey = pubkey;
		ecdsa_verify_req.pubkey_len = pubkey_len;
		ecdsa_verify_req.dst = dst;
		ecdsa_verify_req.dst_len = &out_sz;

		ret = fcs_ecdsa_hash_verify(session_uuid, context_id, keyid,
					    &ecdsa_verify_req);
		if (ret) {
			free(src);
			free(dst);
			free(signature);
			if (keyid == 0)
				free(pubkey);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, out_sz);
		if (ret < 0) {
			fprintf(stderr, "Failed to store ECDSA hash vrfy to file: %d\n",
				ret);
			free(src);
			free(dst);
			free(signature);
			if (keyid == 0)
				free(pubkey);
			return ret;
		}

		if (dst[0] != 0x0d && dst[1] != 0x90)
			fprintf(stderr, "ECDSA Hash data verify failed\n");

		free(src);
		free(dst);
		free(signature);
		if (keyid == 0)
			free(pubkey);
		break;

	case FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_SIGNING_CMD:

		if (!filename || !outfilename) {
			fprintf(stderr, "Missing input or output filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(filename);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", filename);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		/* Allocate memory to read inputdata from file */
		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				filename, strerror(errno));
			return -ENOMEM;
		}

		ret = load_buffer_from_file(filename, src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load input data from file: %d\n",
				ret);
			free(src);
			return ret;
		}

		dst_len = ECDSA_SIGNATURE_MAX_SZ;

		dst = (FCS_OSAL_CHAR *)calloc(dst_len, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				outfilename, strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ecdsa_req.ecc_curve = ecc_curve;
		ecdsa_req.src = src;
		ecdsa_req.src_len = src_len;
		ecdsa_req.dst = dst;
		ecdsa_req.dst_len = &dst_len;

		ret = fcs_ecdsa_sha2_data_sign(session_uuid, context_id, keyid,
					       &ecdsa_req);
		if (ret) {
			free(src);
			free(dst);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, dst_len);
		if (ret < 0) {
			free(src);
			free(dst);
			fprintf(stderr, "Failed to store ECDSA SHA2 data sign: %d\n",
				ret);
			return ret;
		}

		free(src);
		free(dst);
		break;

	case FCS_DEV_CRYPTO_ECDSA_SHA2_DATA_VERIFY_CMD:

		if (!filename_list || !outfilename) {
			fprintf(stderr, "Missing input file list or output filename\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		/* parse to data and signature binary file */
		file_name[file_index] = strtok(filename_list, "#");
		while (file_name[file_index]) {
			file_index++;
			if (file_index <= 2)
				file_name[file_index] = strtok(NULL, "#");
			else
				break;
		}

		if (file_index < 2 || (file_index < 3 && keyid == 0)) {
			fprintf(stderr, "Missing data or signature\n");
			return -EINVAL;
		}

		file_size = get_buffer_size_from_file(file_name[0]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[0]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		src_len = file_size;

		file_size = get_buffer_size_from_file(file_name[1]);
		if (file_size == 0) {
			fprintf(stderr, "File: %s empty\n", file_name[1]);
			return -EINVAL;
		} else if (file_size < 0) {
			return file_size;
		}

		signature_len = file_size;

		src = (FCS_OSAL_CHAR *)calloc(src_len, sizeof(FCS_OSAL_U8));
		if (!src) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				file_name[0], strerror(errno));
			return -ENOMEM;
		}

		signature = (FCS_OSAL_CHAR *)calloc(signature_len,
						    sizeof(FCS_OSAL_CHAR));
		if (!signature) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n",
				file_name[1], strerror(errno));
			free(src);
			return -ENOMEM;
		}

		ret = load_buffer_from_file(file_name[0], src);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n", ret);
			free(src);
			free(signature);
			return ret;
		}

		ret = load_buffer_from_file(file_name[1], signature);
		if (ret < 0) {
			fprintf(stderr, "Failed to load buffer from file: %d\n", ret);
			free(src);
			free(signature);
			return ret;
		}

		dst = (FCS_OSAL_CHAR *)calloc(out_sz, sizeof(FCS_OSAL_U8));
		if (!dst) {
			fprintf(stderr, "can't calloc buffer for %s:  %s\n", outfilename,
				strerror(errno));
			free(src);
			free(signature);
			return -ENOMEM;
		}

		if (keyid == 0) {
			file_size = get_buffer_size_from_file(file_name[2]);
			if (file_size == 0) {
				fprintf(stderr, "File: %s empty\n",
					file_name[2]);
				free(src);
				free(dst);
				free(signature);
				return -EINVAL;
			} else if (file_size < 0) {
				free(src);
				free(dst);
				free(signature);
				return file_size;
			}

			pubkey_len = file_size;

			pubkey = (FCS_OSAL_CHAR *)calloc(pubkey_len,
							 sizeof(FCS_OSAL_U8));
			if (!pubkey) {
				fprintf(stderr, "can't calloc buffer for %s:  %s\n",
					file_name[2], strerror(errno));
				free(src);
				free(dst);
				free(signature);
				return -ENOMEM;
			}

			ret = load_buffer_from_file(file_name[2], pubkey);
			if (ret < 0) {
				fprintf(stderr, "Failed to load buffer from file: %d\n",
					ret);
				free(src);
				free(dst);
				free(signature);
				free(pubkey);
				return ret;
			}
		}

		ecdsa_verify_req.ecc_curve = ecc_curve;
		ecdsa_verify_req.src = src;
		ecdsa_verify_req.src_len = src_len;
		ecdsa_verify_req.signature = signature;
		ecdsa_verify_req.signature_len = signature_len;
		ecdsa_verify_req.pubkey = pubkey;
		ecdsa_verify_req.pubkey_len = pubkey_len;
		ecdsa_verify_req.dst = dst;
		ecdsa_verify_req.dst_len = &out_sz;

		ret = fcs_ecdsa_sha2_data_verify(session_uuid, context_id,
						 keyid, &ecdsa_verify_req);
		if (ret) {
			free(src);
			free(dst);
			free(signature);
			if (keyid == 0)
				free(pubkey);
			return ret;
		}

		ret = store_buffer_to_file(outfilename, dst, out_sz);
		if (ret < 0) {
			fprintf(stderr, "Failed to store ECDSA data verify %d\n",
				ret);
			free(src);
			free(dst);
			free(signature);
			if (keyid == 0)
				free(pubkey);
			return ret;
		}

		if (dst[0] != 0x0d && dst[1] != 0x90)
			fprintf(stderr, "ECDSA SHA2 Data verify failed\n");

		free(src);
		free(dst);
		free(signature);
		if (keyid == 0)
			free(pubkey);
		break;

	case FCS_DEV_VALIDATE_REQUEST_CMD:
		if (!filename) {
			fprintf(stderr, "Missing input file is missing\n");
			return -EINVAL;
		}

		if (is_session_id_valid(session_uuid)) {
			fprintf(stderr, "Session ID Invalid\n");
			return -EINVAL;
		}

		ret = fcs_validate_hps_image(session_uuid, filename);
		if (ret)
			return ret;
		break;

	case FCS_DEV_COMMAND_NONE:
		/* fall through */

	default:
		fprintf(stderr, "Invalid Input Command [0x%X]\n", command);
		fcs_client_usage();
		break;
	}

	return 0;
}
