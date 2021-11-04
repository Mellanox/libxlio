/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef XLIO_TLS_H
#define XLIO_TLS_H

#include "config.h"

#ifdef DEFINED_UTLS
#include <linux/tls.h>
#endif /* DEFINED_UTLS */

/* Don't wrap the following defines with DEFINED_UTLS. */
#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef TLS_GET_RECORD_TYPE
#define TLS_GET_RECORD_TYPE 2
#endif
#ifndef TLS_SET_RECORD_TYPE
#define TLS_SET_RECORD_TYPE 1
#endif

#ifdef DEFINED_UTLS

#ifndef TLS_TX
#define TLS_TX 1
#endif
#ifndef TLS_RX
#define TLS_RX 2
#endif

#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif
#ifndef TLS_1_3_VERSION
#define TLS_1_3_VERSION 0x0304
#endif
#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#endif

enum {
	TLS_AES_GCM_IV_LEN      = 8U,
	TLS_AES_GCM_SALT_LEN    = 4U,
	TLS_AES_GCM_REC_SEQ_LEN = 8U,
	TLS_AES_GCM_KEY_MAX     = 32U,
};

enum tls_record_content_type {
	TLS_CHANGE_CIPHER_SPEC = 20,
	TLS_ALERT              = 21,
	TLS_HANDSHAKE          = 22,
	TLS_APPLICATION_DATA   = 23,
};

enum tls_alert_level {
	TLS_ALERT_LEVEL_WARNING = 1,
	TLS_ALERT_LEVEL_FATAL   = 2,
};

enum tls_alert_description {
	/*
	 * RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
	 */
	TLS_CLOSE_NOTIFY = 0,
	TLS_UNEXPECTED_MESSAGE = 10, /* fatal*/
	TLS_BAD_RECORD_MAC = 20, /* fatal*/
	TLS_RECORD_OVERFLOW = 22,
	TLS_HANDSHAKE_FAILURE = 40, /* fatal*/
	TLS_BAD_CERTIFICATE = 42,
	TLS_UNSUPPORTED_CERTIFICATE = 43,
	TLS_CERTIFICATE_REVOKED = 44,
	TLS_CERTIFICATE_EXPIRED = 45,
	TLS_CERTIFICATE_UNKNOWN = 46,
	TLS_ILLEGAL_PARAMETER = 47, /* fatal*/
	TLS_UNKNOWN_CA = 48, /* fatal*/
	TLS_ACCESS_DENIED = 49, /* fatal*/
	TLS_DECODE_ERROR = 50, /* fatal*/
	TLS_DECRYPT_ERROR = 51,
	TLS_PROTOCOL_VERSION = 70, /* fatal*/
	TLS_INSUFFICIENT_SECURITY = 71, /* fatal*/
	TLS_INTERNAL_ERROR = 80, /* fatal*/
	TLS_INAPPROPRIATE_FALLBACK = 86, /* fatal*/
	TLS_USER_CANCELED = 90,
	TLS_MISSING_EXTENSION = 109, /* fatal*/
	TLS_CERTIFICATE_REQUIRED = 116, /* fatal*/
	TLS_UNKNOWN_PSK_IDENTITY = 115, /* fatal*/
	TLS_NO_APPLICATION_PROTOCOL = 120, /* fatal*/
	TLS_UNSUPPORTED_EXTENSION = 110,
	TLS_UNRECOGNIZED_NAME = 112,
	TLS_BAD_CERTIFICATE_STATUS_RESPONSE = 113,

	// Deprecated since TLS v1.3
	TLS_DECOMPRESSION_FAILURE = 30, /* fatal*/
	TLS_NO_RENEGOTIATION = 100,
	TLS_CERTIFICATE_UNOBTAINABLE = 111,
	TLS_BAD_CERTIFICATE_HASH_VALUE = 114,

	// Deprecated since TLS v1.2
	TLS_DECRYPTION_FAILED = 21,
	TLS_NO_CERTIFICATE = 41,
	TLS_EXPORT_RESTRICTION = 60, /* fatal*/
};

struct xlio_tls_info {
	uint32_t key_len;
	uint16_t tls_version;
	uint16_t tls_cipher;
	union {
		unsigned char iv[TLS_AES_GCM_IV_LEN];
		uint64_t iv64;
	};
	unsigned char key[TLS_AES_GCM_KEY_MAX];
	unsigned char salt[TLS_AES_GCM_SALT_LEN];
	unsigned char rec_seq[TLS_AES_GCM_REC_SEQ_LEN];
};

/* Format of the buffer returned by ring::tls_get_progress_params_rx(). */
/* This brings low-level knowledge to the TLS layer what is not a good idea. */
struct xlio_tls_progress_params {
	__be32 tis_tir_number;
	__be32 next_record_tcp_sn;
	__be32 hw_resync_tcp_sn;
	/*
	 * 7:6 bits - record_tracker_state
	 * 5:4 bits - auth_state
	 */
	uint8_t state;
	uint8_t hw_offset_record_number[3];
} __attribute__((packed));

#endif /* DEFINED_UTLS */

#endif /* XLIO_TLS_H */
