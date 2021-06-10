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

#include "vma/dev/ib_ctx_handler.h"
#include "sockinfo_tcp.h"
#include "sockinfo_ulp.h"

#include <algorithm>
#include <endian.h>
#include <errno.h>
#include <sys/socket.h>

#define MODULE_NAME	"si_ulp"

#define si_ulp_logdbg	__log_info_dbg
#define si_ulp_logerr	__log_info_err

/*
 * sockinfo_tcp_ops
 */

sockinfo_tcp_ops::sockinfo_tcp_ops(sockinfo_tcp *sock)
{
	m_sock = sock;
}

/*virtual*/
int sockinfo_tcp_ops::setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen)
{
	return m_sock->tcp_setsockopt(__level, __optname, __optval, __optlen);
}

/*virtual*/
ssize_t sockinfo_tcp_ops::tx(vma_tx_call_attr_t &tx_arg)
{
	return m_sock->tcp_tx(tx_arg);
}

/*virtual*/
int sockinfo_tcp_ops::postrouting(struct pbuf *p, struct tcp_seg *seg, vma_send_attr &attr)
{
	NOT_IN_USE(p);
	NOT_IN_USE(seg);
	NOT_IN_USE(attr);
	return 0;
}

#ifdef DEFINED_UTLS

/*
 * sockinfo_tcp_ulp_tls
 */

sockinfo_tcp_ulp_tls g_sockinfo_tcp_ulp_tls;

int sockinfo_tcp_ulp_tls::attach(sockinfo_tcp *sock)
{
	sockinfo_tcp_ops_tls *ops;
	sockinfo_tcp_ops *ops_old;

	if (unlikely(!sock->is_rts())) {
		errno = ENOTCONN;
		return -1;
	}

	ops = new sockinfo_tcp_ops_tls(sock);
	if (unlikely(ops == NULL)) {
		errno = ENOMEM;
		return -1;
	}
	ops_old = sock->get_ops();
	sock->set_ops(ops);
	delete ops_old;

	return 0;
}

/*static*/
sockinfo_tcp_ulp_tls *sockinfo_tcp_ulp_tls::instance(void)
{
	return &g_sockinfo_tcp_ulp_tls;
}

/*
 * tls_record
 */

enum {
	TLS_RECORD_HDR_LEN  = 5UL,
	TLS_RECORD_IV_LEN   = 8UL,
	TLS_RECORD_TAG_LEN  = 16UL,
	TLS_RECORD_OVERHEAD = TLS_RECORD_HDR_LEN + TLS_RECORD_IV_LEN +
			      TLS_RECORD_TAG_LEN,
	TLS_RECORD_SMALLEST = 256U,
};

class tls_record : public mem_desc {
public:
	tls_record(sockinfo_tcp *sock, uint32_t seqno, uint64_t record_number, uint8_t *iv)
	{
		m_sock = sock;
		m_p_ring = m_sock->get_ring();
		/* Allocate record with a taken reference. */
		atomic_set(&m_ref, 1);
		m_seqno = seqno;
		m_record_number = record_number;
		m_size = TLS_RECORD_HDR_LEN + TLS_RECORD_IV_LEN + TLS_RECORD_TAG_LEN;
		p_data = sock->tcp_tx_mem_buf_alloc(PBUF_RAM);
		if (likely(p_data != NULL)) {
			p_data->p_buffer[0] = 0x17;
			p_data->p_buffer[1] = 0x3;
			p_data->p_buffer[2] = 0x3;
			p_data->p_buffer[3] = 0;
			p_data->p_buffer[4] = TLS_RECORD_TAG_LEN + TLS_RECORD_IV_LEN;
			memcpy(&p_data->p_buffer[5], iv, TLS_RECORD_IV_LEN);
		}
		/* TODO Make a pool of preallocated records with inited header. */
	}

	~tls_record()
	{
		/*
		 * Because of batching, buffers can be freed after their socket
		 * is closed. Therefore, we cannot return p_data to the socket.
		 */
		if (likely(p_data != NULL)) {
			m_p_ring->mem_buf_desc_return_single_to_owner_tx(p_data);
		}
	}

	void get(void)
	{
		(void)atomic_fetch_and_inc(&m_ref);
	}

	void put(void)
	{
		int ref = atomic_fetch_and_dec(&m_ref);

		if (ref == 1)
			delete this;
	}

	uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, void *addr, size_t len)
	{
		NOT_IN_USE(desc);
		NOT_IN_USE(ib_ctx);
		NOT_IN_USE(addr);
		NOT_IN_USE(len);
		return LKEY_USE_DEFAULT;
	}

	inline size_t append_data(void *data, size_t len)
	{
		len = std::min(len, avail_space());
		memcpy(p_data->p_buffer + m_size - TLS_RECORD_TAG_LEN, data, len);
		m_size += len;
		set_length();

		return len;
	}

	inline size_t avail_space(void)
	{
		/* Don't produce records larger than 16KB according to the protocol. */
		return std::min(p_data->sz_buffer, (size_t)16384) - m_size;
	}

	inline void set_type(uint8_t type)
	{
		p_data->p_buffer[0] = type;
	}

private:
	inline void set_length(void)
	{
		uint16_t len = m_size - TLS_RECORD_HDR_LEN;

		p_data->p_buffer[3] = len >> 8UL;
		p_data->p_buffer[4] = len & 0xff;
	}

public:
	atomic_t m_ref;
	uint32_t m_seqno;
	uint64_t m_record_number;
	size_t m_size;
	mem_buf_desc_t *p_data;
	sockinfo_tcp *m_sock;
	ring *m_p_ring;
};

/*
 * sockinfo_tcp_ops_tls
 */

sockinfo_tcp_ops_tls::sockinfo_tcp_ops_tls(sockinfo_tcp *sock) :
	sockinfo_tcp_ops(sock)
{
	m_is_tls = false;
	p_tis = NULL;
	p_dek = NULL;
}

sockinfo_tcp_ops_tls::~sockinfo_tcp_ops_tls()
{
	if (m_is_tls) {
		delete p_tis;
		delete p_dek;
	}
}

int sockinfo_tcp_ops_tls::setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen)
{
	if (__level == SOL_TLS && __optname == TLS_TX) {
		/* XXX bond devices cannot be supported in such a way */
		ib_ctx_handler *ib_ctx = m_sock->get_ctx();
		ring *ring = m_sock->get_ring();
		dpcp::status status;
		uint64_t record_number;
		const struct tls_crypto_info *base_info =
			(const struct tls_crypto_info *)__optval;
		const struct tls12_crypto_info_aes_gcm_128 *crypto_info =
			(const struct tls12_crypto_info_aes_gcm_128 *)__optval;

		if (__optlen < sizeof(tls12_crypto_info_aes_gcm_128)) {
			errno = EINVAL;
			return -1;
		}
		if (base_info->version != TLS_1_2_VERSION) {
			si_ulp_logdbg("Unsupported TLS version.");
			errno = ENOPROTOOPT;
			return -1;
		}
		if (base_info->cipher_type != TLS_CIPHER_AES_GCM_128) {
			si_ulp_logdbg("Unsupported TLS cipher ID: %u.", base_info->cipher_type);
			errno = ENOPROTOOPT;
			return -1;
		}

		/*
		 * TODO When new ciphers are added, make sure IV size is the
		 * same as TLS_RECORD_IV_LEN.
		 */

		p_tis = ib_ctx->create_tis();
		p_dek = ib_ctx->create_dek(crypto_info->key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
		if (p_tis == NULL || p_dek == NULL) {
			goto err;
		}
		status = p_tis->get_tisn(m_tisn);
		if (status != dpcp::DPCP_OK) {
			si_ulp_logerr("Cannot get TIS number.");
			goto err;
		}

		m_expected_seqno = m_sock->get_next_tcp_seqno();
		memcpy(m_iv, crypto_info->iv, TLS_RECORD_IV_LEN);
		memcpy(&m_crypto_info, crypto_info, sizeof(*crypto_info));
		memcpy(&record_number, crypto_info->rec_seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
		m_next_record_number = be64toh(record_number);

		ring->tls_context_setup(__optval, m_tisn, p_dek->get_key_id(), m_expected_seqno);
		m_is_tls = true;

		return 0;
	}
	if (__level == SOL_TLS && __optname != TLS_TX) {
		errno = ENOPROTOOPT;
		return -1;
	}
	return m_sock->tcp_setsockopt(__level, __optname, __optval, __optlen);

err:
	if (p_tis != NULL) {
		delete p_tis;
		p_tis = NULL;
	}
	if (p_dek != NULL) {
		delete p_dek;
		p_dek = NULL;
	}
	/* If TLS setup fails we will fallback to software implementation. */
	errno = ENOPROTOOPT;
	return -1;
}

ssize_t sockinfo_tcp_ops_tls::tx(vma_tx_call_attr_t &tx_arg)
{
	/*
	 * TODO This method must be called under socket lock to avoid situation
	 * where multiple send() are called simultaneously and multiple tls
	 * records are associated with the same seqno (since pcb->snd_lbb isn't
	 * updated).
	 */

	vma_tx_call_attr_t tls_arg;
	struct iovec *p_iov;
	struct iovec tls_iov[1];
	uint64_t last_record_number;
	ssize_t ret;
	size_t pos;
	int errno_save;
	bool block_this_run;

	if (!m_is_tls) {
		return m_sock->tcp_tx(tx_arg);
	}

	errno_save = errno;
	block_this_run = BLOCK_THIS_RUN(m_sock->is_blocking(), tx_arg.attr.msg.flags);

	tls_arg.opcode = TX_FILE; /* XXX Not to use hugepage zerocopy path */
	tls_arg.attr.msg.flags = MSG_ZEROCOPY;
	tls_arg.vma_flags = TX_FLAG_NO_PARTIAL_WRITE;
	tls_arg.attr.msg.iov = tls_iov;
	tls_arg.attr.msg.sz_iov = 1;
	tls_arg.priv.attr = PBUF_DESC_MDESC;

	p_iov = tx_arg.attr.msg.iov;
	last_record_number = m_next_record_number;
	ret = 0;

	for (ssize_t i = 0; i < tx_arg.attr.msg.sz_iov; ++i) {
		pos = 0;
		while (pos < p_iov[i].iov_len) {
			tls_record *rec;
			ssize_t ret2;
			size_t sndbuf = m_sock->sndbuf_available();
			size_t tosend = p_iov[i].iov_len - pos;

			/*
			 * XXX This approach can lead to issue with epoll()
			 * since such a socket will always be ready for write
			 */
			if (!block_this_run && sndbuf < TLS_RECORD_SMALLEST &&
			    (sndbuf < TLS_RECORD_OVERHEAD || (sndbuf - TLS_RECORD_OVERHEAD) < tosend)) {
				/*
				 * We don't want to create too small TLS records
				 * when we do partial write.
				 */
				if (ret == 0) {
					errno = EAGAIN;
					ret = -1;
				}
				goto done;
			}

			rec = new tls_record(m_sock, m_sock->get_next_tcp_seqno(),
					     m_next_record_number, m_crypto_info.iv);
			if (unlikely(rec == NULL || rec->p_data == NULL)) {
				if (ret == 0) {
					errno = ENOMEM;
					ret = -1;
				}
				if (rec != NULL) {
					rec->put();
				}
				goto done;
			}
			++m_next_record_number;

			/* Control sendmsg() support */
			if (tx_arg.opcode == TX_SENDMSG && tx_arg.attr.msg.hdr != NULL) {
				struct msghdr *__msg = (struct msghdr *)tx_arg.attr.msg.hdr;
				struct cmsghdr *cmsg;
				if (__msg->msg_controllen != 0) {
					for (cmsg = CMSG_FIRSTHDR(__msg); cmsg; cmsg = CMSG_NXTHDR(__msg, cmsg)) {
						if (cmsg->cmsg_level == SOL_TLS &&
						    cmsg->cmsg_type == TLS_SET_RECORD_TYPE) {
							rec->set_type(*CMSG_DATA(cmsg));
						}
					}
				}
			}

			if (!block_this_run) {
				/* sndbuf overflow is not possible since we have a check above. */
				tosend = std::min(tosend, sndbuf - TLS_RECORD_OVERHEAD);
			}
			tosend = rec->append_data((uint8_t *)p_iov[i].iov_base + pos, tosend);
			pos += tosend;
			tls_arg.attr.msg.iov[0].iov_base = rec->p_data->p_buffer;
			tls_arg.attr.msg.iov[0].iov_len = rec->m_size;
			tls_arg.priv.mdesc = (void*)rec;

retry:
			ret2 = m_sock->tcp_tx(tls_arg);
			if (block_this_run && (ret2 != (ssize_t)tls_arg.attr.msg.iov[0].iov_len)) {
				if ((ret2 >= 0) || (errno == EINTR && !g_b_exit)) {
					ret2 = ret2 < 0 ? 0 : ret2;
					tls_arg.attr.msg.iov[0].iov_len -= ret2;
					tls_arg.attr.msg.iov[0].iov_base =
						(void *)((uint8_t *)tls_arg.attr.msg.iov[0].iov_base + ret2);
					goto retry;
				}
				if (tls_arg.attr.msg.iov[0].iov_len != rec->m_size) {
					/* We cannot recover from a fail in the middle of a TLS record */
					if (!g_b_exit)
						m_sock->abort_connection();
					ret += (rec->m_size - tls_arg.attr.msg.iov[0].iov_len);
					rec->put();
					goto done;
				}
			}
			if (ret2 < 0) {
				if (ret == 0) {
					/* Keep errno from the TCP layer. */
					ret = -1;
				}
				/*
				 * sockinfo_tcp::tcp_tx() can return EINTR error even if some portion
				 * of data is queued. This is wrong behavior and we must not destroy
				 * record here until this issue is fixed. Instead of destroying, put
				 * the reference and in case if TCP layer silently queues TCP segments,
				 * the record will be destroyed only when the last pbuf is freed.
				 */
				rec->put();
				--m_next_record_number;
				goto done;
			}
			ret += (ssize_t)tosend;
			/*
			 * We allocate tls_records with a taken reference, so we
			 * need to release it. This is done to avoid issues
			 * when a pbuf takes a reference to the record and then
			 * the pbuf is freed due to segment allocation error.
			 */
			rec->put();
		}
	}
done:

	/* Statistics */
	if (ret > 0) {
		errno = errno_save;
		m_sock->m_p_socket_stats->tls_counters.n_tls_tx_records += m_next_record_number - last_record_number;
		m_sock->m_p_socket_stats->tls_counters.n_tls_tx_bytes += ret;
	}
	return ret;
}

int sockinfo_tcp_ops_tls::postrouting(struct pbuf *p, struct tcp_seg *seg, vma_send_attr &attr)
{
	NOT_IN_USE(p);
	if (m_is_tls && seg != NULL && p->type != PBUF_RAM) {
		if (seg->len != 0) {
			if (unlikely(seg->seqno != m_expected_seqno)) {
				ring *ring = m_sock->get_ring();
				uint64_t record_number_be64;
				unsigned mss = m_sock->get_mss();

				/* For zerocopy the 1st pbuf is always a TCP header and the pbuf is on stack */
				assert(p->type == PBUF_ROM); /* TCP header pbuf */
				assert(p->next != NULL && p->next->desc.attr == PBUF_DESC_MDESC);
				tls_record *rec = dynamic_cast<tls_record *>((mem_desc*)p->next->desc.mdesc);

				assert(rec != NULL); /* XXX */

				si_ulp_logdbg("TX resync flow: record_number=%lu seqno%u", rec->m_record_number, seg->seqno);
				record_number_be64 = htobe64(rec->m_record_number);
				memcpy(&m_crypto_info.rec_seq, &record_number_be64, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
				ring->tls_context_setup(&m_crypto_info, m_tisn, p_dek->get_key_id(), rec->m_seqno);

				uint32_t nr = (seg->seqno - rec->m_seqno + mss - 1) / mss;
				uint8_t *addr = rec->p_data->p_buffer;
				uint32_t len;
				uint32_t lkey = LKEY_USE_DEFAULT;

				if (nr == 0) {
					ring->post_nop_fence();
				}
				for (uint32_t i = 0; i < nr; ++i) {
					len = (i == nr - 1) ? (seg->seqno - rec->m_seqno) % mss : mss;
					if (len == 0)
						len = mss;
					ring->tls_tx_post_dump_wqe(m_tisn, (void *)addr, len, lkey);
					addr += mss;
				}

				m_expected_seqno = seg->seqno;

				/* Statistics */
				++m_sock->m_p_socket_stats->tls_counters.n_tls_tx_resync;
				m_sock->m_p_socket_stats->tls_counters.n_tls_tx_resync_replay += !!nr;
			}
			m_expected_seqno += seg->len;
			/* XXX Bonding cannot be supported in this way */
			attr.tisn = m_tisn;
		}
	}
	return 0;
}

#endif /* DEFINED_UTLS */
