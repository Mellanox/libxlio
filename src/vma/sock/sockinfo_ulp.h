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


#ifndef VMA_SOCKINFO_ULP_H
#define VMA_SOCKINFO_ULP_H

#include "socket_fd_api.h"		/* vma_tx_call_attr_t */
#include "vma/proto/dst_entry.h"	/* vma_send_attr */

#ifdef DEFINED_UTLS
#include <mellanox/dpcp.h>
#include <linux/tls.h>
#endif /* DEFINED_UTLS */

#include <stdint.h>

/*
 * TODO Make ULP layer generic (not TCP specific) and implement ULP manager.
 */

#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef TLS_1_2_VERSION
#define TLS_1_2_VERSION 0x0303
#endif
#ifndef TLS_CIPHER_AES_GCM_128
#define TLS_CIPHER_AES_GCM_128 51
#endif

/* Forward declarations */
class sockinfo_tcp;
struct pbuf;

class sockinfo_tcp_ulp {
public:
	virtual int attach(sockinfo_tcp *sock) = 0;
};

class sockinfo_tcp_ops {
public:
	sockinfo_tcp_ops(sockinfo_tcp *sock);
	virtual ~sockinfo_tcp_ops() {}

	virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	virtual ssize_t tx(vma_tx_call_attr_t &tx_arg);
	virtual int postrouting(struct pbuf *p, struct tcp_seg *seg, vma_send_attr &attr);

protected:
	sockinfo_tcp *m_sock;
};

#ifdef DEFINED_UTLS

class sockinfo_tcp_ulp_tls : public sockinfo_tcp_ulp {
public:
	int attach(sockinfo_tcp *sock);
	static sockinfo_tcp_ulp_tls *instance(void);
};

class sockinfo_tcp_ops_tls : public sockinfo_tcp_ops {
public:
	sockinfo_tcp_ops_tls(sockinfo_tcp *sock);
	~sockinfo_tcp_ops_tls();

	int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
	ssize_t tx(vma_tx_call_attr_t &tx_arg);
	int postrouting(struct pbuf *p, struct tcp_seg *seg, vma_send_attr &attr);

private:
	dpcp::tis *p_tis;
	dpcp::dek *p_dek;
	uint32_t m_tisn;
	uint32_t m_expected_seqno;
	bool m_is_tls;
	uint64_t m_next_record_number;
	uint8_t m_iv[8];
	struct tls12_crypto_info_aes_gcm_128 m_crypto_info;
};

#endif /* DEFINED_UTLS */

#endif /* VMA_SOCKINFO_ULP_H */
