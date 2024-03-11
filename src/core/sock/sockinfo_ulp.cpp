/*
 * Copyright (c) 2001-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include "sockinfo_tcp.h"
#include "sockinfo_ulp.h"

#include <algorithm>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <sys/socket.h>

#define MODULE_NAME "si_ulp"

#define si_ulp_logdbg  __log_info_dbg
#define si_ulp_loginfo __log_info_info
#define si_ulp_logerr  __log_info_err

/*inline*/
ring *sockinfo_tcp_ops::get_tx_ring()
{
    return m_p_sock->get_tx_ring();
}

/*virtual*/
int sockinfo_tcp_ops::setsockopt(int __level, int __optname, const void *__optval,
                                 socklen_t __optlen)
{
    return m_p_sock->tcp_setsockopt(__level, __optname, __optval, __optlen);
}

/*virtual*/
ssize_t sockinfo_tcp_ops::tx(xlio_tx_call_attr_t &tx_arg)
{
    return m_p_sock->tcp_tx(tx_arg);
}

/*virtual*/
int sockinfo_tcp_ops::postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr)
{
    NOT_IN_USE(p);
    NOT_IN_USE(seg);
    NOT_IN_USE(attr);
    return 0;
}

/*virtual*/
bool sockinfo_tcp_ops::handle_send_ret(ssize_t ret, struct tcp_seg *seg)
{
    NOT_IN_USE(ret);
    NOT_IN_USE(seg);
    return true;
}

#ifdef DEFINED_UTLS

#include <openssl/evp.h>

struct xlio_tls_api {
    EVP_CIPHER_CTX *(*EVP_CIPHER_CTX_new)();
    void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX *);
    int (*EVP_CIPHER_CTX_reset)(EVP_CIPHER_CTX *);
    const EVP_CIPHER *(*EVP_aes_128_gcm)();
    const EVP_CIPHER *(*EVP_aes_256_gcm)();
    int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *,
                              const unsigned char *);
    int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
    int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX *, int, int, void *);
    int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
    int (*EVP_EncryptInit_ex)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *, const unsigned char *,
                              const unsigned char *);
    int (*EVP_EncryptUpdate)(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
    int (*EVP_EncryptFinal_ex)(EVP_CIPHER_CTX *, unsigned char *, int *);
};

static struct xlio_tls_api *g_tls_api = nullptr;
static struct xlio_tls_api s_tls_api;

template <typename T> static void dlsym_handle(T &ptr, const char *name, void *handle)
{
    ptr = reinterpret_cast<T>(dlsym(handle, name));
}
template <typename T> static void dlsym_default(T &ptr, const char *name)
{
    dlsym_handle(ptr, name, RTLD_DEFAULT);
}

#define XLIO_TLS_API_FIND(__name) dlsym_default(s_tls_api.__name, #__name);

void xlio_tls_api_setup()
{
    XLIO_TLS_API_FIND(EVP_CIPHER_CTX_new);
    XLIO_TLS_API_FIND(EVP_CIPHER_CTX_free);
    XLIO_TLS_API_FIND(EVP_CIPHER_CTX_reset);
    XLIO_TLS_API_FIND(EVP_aes_128_gcm);
    XLIO_TLS_API_FIND(EVP_aes_256_gcm);
    XLIO_TLS_API_FIND(EVP_DecryptInit_ex);
    XLIO_TLS_API_FIND(EVP_DecryptUpdate);
    XLIO_TLS_API_FIND(EVP_CIPHER_CTX_ctrl);
    XLIO_TLS_API_FIND(EVP_DecryptFinal_ex);
    XLIO_TLS_API_FIND(EVP_EncryptInit_ex);
    XLIO_TLS_API_FIND(EVP_EncryptUpdate);
    XLIO_TLS_API_FIND(EVP_EncryptFinal_ex);
    if (s_tls_api.EVP_CIPHER_CTX_new && s_tls_api.EVP_CIPHER_CTX_free &&
        s_tls_api.EVP_CIPHER_CTX_reset && s_tls_api.EVP_aes_128_gcm && s_tls_api.EVP_aes_256_gcm &&
        s_tls_api.EVP_DecryptInit_ex && s_tls_api.EVP_DecryptUpdate &&
        s_tls_api.EVP_CIPHER_CTX_ctrl && s_tls_api.EVP_DecryptFinal_ex &&
        s_tls_api.EVP_EncryptInit_ex && s_tls_api.EVP_EncryptUpdate &&
        s_tls_api.EVP_EncryptFinal_ex) {
        g_tls_api = &s_tls_api;
    }
}

static inline uint8_t get_alert_level(uint8_t alert_type)
{
    switch (alert_type) {
    case TLS_CLOSE_NOTIFY:
    case TLS_RECORD_OVERFLOW:
    case TLS_BAD_CERTIFICATE:
    case TLS_UNSUPPORTED_CERTIFICATE:
    case TLS_CERTIFICATE_REVOKED:
    case TLS_CERTIFICATE_EXPIRED:
    case TLS_CERTIFICATE_UNKNOWN:
    case TLS_DECRYPT_ERROR:
    case TLS_USER_CANCELED:
    case TLS_UNSUPPORTED_EXTENSION:
    case TLS_UNRECOGNIZED_NAME:
    case TLS_BAD_CERTIFICATE_STATUS_RESPONSE:
    case TLS_NO_RENEGOTIATION:
    case TLS_CERTIFICATE_UNOBTAINABLE:
    case TLS_BAD_CERTIFICATE_HASH_VALUE:
    case TLS_DECRYPTION_FAILED:
    case TLS_NO_CERTIFICATE:
        return TLS_ALERT_LEVEL_WARNING;
    default:
        break;
    }
    return TLS_ALERT_LEVEL_FATAL;
}

/*
 * tls_record
 */

enum : size_t {
    TLS_RECORD_HDR_LEN = 5U,
    TLS_RECORD_IV_LEN = TLS_AES_GCM_IV_LEN,
    TLS_13_RECORD_IV_LEN = 0U,
    TLS_RECORD_TAG_LEN = 16U,
    TLS_RECORD_NONCE_LEN = 12U, /* SALT + IV */
    /* TLS 1.2 record overhead. */
    TLS_12_RECORD_OVERHEAD = TLS_RECORD_HDR_LEN + TLS_RECORD_IV_LEN + TLS_RECORD_TAG_LEN,
    /* TLS 1.3 record overhead. */
    TLS_13_RECORD_OVERHEAD = TLS_RECORD_HDR_LEN + 1U + TLS_RECORD_TAG_LEN,
    /* If possible, we won't produce TLS records smaller that this value. */
    TLS_RECORD_SMALLEST = 256U,
    TLS_RECORD_MAX = 16384U,
    /* Block size big enough to hold TLS header/trailer for zerocopy records. */
    TLS_ZC_BLOCK = 32U,
};

class tls_record : public mem_desc {
public:
    tls_record(sockinfo_tcp_ops_tls *tls_sock, uint32_t seqno, uint64_t record_number, uint8_t *iv,
               mem_desc *zc_owner)
    {
        m_p_tx_ring = tls_sock->get_tx_ring();
        /* Allocate record with a taken reference. */
        atomic_set(&m_ref, 1);
        m_seqno = seqno;
        m_record_number = record_number;
        m_size = TLS_RECORD_HDR_LEN + TLS_RECORD_TAG_LEN;
        m_p_data = nullptr;
        tls_sock->get_record_buf(m_p_buf, m_p_data, zc_owner);
        if (likely(m_p_buf && m_p_data)) {
            if (iv) {
                m_size += TLS_RECORD_IV_LEN;
                memcpy(&m_p_data[5], iv, TLS_RECORD_IV_LEN);
            } else {
                /* For TLS1.3 we need to add a room for the inner type field. */
                m_size += 1;
            }
            m_p_data[0] = 0x17;
            m_p_data[1] = 0x3;
            m_p_data[2] = 0x3;
            m_p_data[3] = 0;
            m_p_data[4] = m_size - TLS_RECORD_HDR_LEN;
        }
        m_p_zc_owner = zc_owner;
        if (m_p_zc_owner) {
            m_p_zc_owner->get();
        }
        m_p_zc_data = nullptr;
    }

    ~tls_record() override
    {
        /*
         * Because of batching, buffers can be freed after their socket
         * is closed. Therefore, we cannot return m_p_buf to the socket.
         */
        if (likely(m_p_buf)) {
            m_p_tx_ring->mem_buf_desc_return_single_to_owner_tx(m_p_buf);
        }
        if (m_p_zc_owner) {
            m_p_zc_owner->put();
        }
    }

    void get() override { (void)atomic_fetch_and_inc(&m_ref); }

    void put() override
    {
        int ref = atomic_fetch_and_dec(&m_ref);

        if (ref == 1) {
            delete this;
        }
    }

    uint32_t get_lkey(mem_buf_desc_t *desc, ib_ctx_handler *ib_ctx, const void *addr,
                      size_t len) override
    {
        const uintptr_t uaddr = (uintptr_t)addr;
        const uintptr_t ubuf = (uintptr_t)m_p_buf->p_buffer;

        if (ubuf <= uaddr && uaddr < ubuf + m_p_buf->sz_buffer) {
            return LKEY_TX_DEFAULT;
        } else {
            return m_p_zc_owner->get_lkey(desc, ib_ctx, addr, len);
        }
    }

    inline size_t append_data(void *data, size_t len, bool is_tls13)
    {
        len = std::min(len, avail_space());
        if (len > 0) {
            if (m_p_zc_owner) {
                m_p_zc_data = reinterpret_cast<uint8_t *>(data);
            } else {
                memcpy(m_p_data + m_size - TLS_RECORD_TAG_LEN - !!is_tls13, data, len);
            }
            m_size += len;
            set_length();
        }
        return len;
    }

    inline size_t avail_space()
    {
        /* Don't produce records larger than 16KB according to the protocol. */
        size_t max_len = m_p_zc_owner ? (size_t)TLS_RECORD_MAX
                                      : std::min<size_t>(m_p_buf->sz_buffer, TLS_RECORD_MAX);

        return max_len - m_size;
    }

    inline void set_type(uint8_t type, bool is_tls13)
    {
        if (is_tls13) {
            unsigned offset =
                m_p_zc_owner ? (unsigned)TLS_RECORD_HDR_LEN : (m_size - TLS_RECORD_TAG_LEN - 1U);
            m_p_data[offset] = type;
        } else {
            m_p_data[0] = type;
        }
    }

    inline void fill_iov(struct iovec *iov, size_t iov_max, bool is_tls13)
    {
        if (m_p_zc_owner) {
            /*
             * For zerocopy case we create 3 scatter-gather elements in this order:
             * [0] TLS header which includes IV for TLS 1.2
             * [1] Payload
             * [2] Trailer which contains TAG and TLS 1.3 type if applicable
             */
            assert(iov_max >= 3);
            (void)iov_max;
            iov[0].iov_base = m_p_data;
            iov[0].iov_len =
                TLS_RECORD_HDR_LEN + (is_tls13 ? TLS_13_RECORD_IV_LEN : TLS_RECORD_IV_LEN);
            iov[1].iov_base = m_p_zc_data;
            iov[1].iov_len = m_size - (is_tls13 ? TLS_13_RECORD_OVERHEAD : TLS_12_RECORD_OVERHEAD);
            iov[2].iov_base = m_p_data + iov[0].iov_len;
            iov[2].iov_len = TLS_RECORD_TAG_LEN + !!is_tls13;
        } else {
            iov[0].iov_base = m_p_data;
            iov[0].iov_len = m_size;
        }
    }

private:
    inline void set_length()
    {
        uint16_t len = m_size - TLS_RECORD_HDR_LEN;

        m_p_data[3] = len >> 8UL;
        m_p_data[4] = len & 0xff;
    }

public:
    atomic_t m_ref;
    uint32_t m_seqno;
    uint64_t m_record_number;
    size_t m_size;
    mem_buf_desc_t *m_p_buf;
    uint8_t *m_p_data;
    uint8_t *m_p_zc_data;
    mem_desc *m_p_zc_owner;
    ring *m_p_tx_ring;
};

/*
 * sockinfo_tcp_ops_tls
 */

sockinfo_tcp_ops_tls::sockinfo_tcp_ops_tls(sockinfo_tcp *sock)
    : sockinfo_tcp_ops(sock)
{
    /* We don't support ring migration with TLS offload */
    m_p_tx_ring = sock->get_tx_ring();
    m_p_rx_ring = sock->get_rx_ring();
    memset(&m_tls_info_tx, 0, sizeof(m_tls_info_tx));
    memset(&m_tls_info_rx, 0, sizeof(m_tls_info_rx));

    m_is_tls_tx = false;
    m_is_tls_rx = false;
    m_tls_rec_overhead = 0;

    m_p_tis = nullptr;
    m_zc_stor = nullptr;
    m_zc_stor_offset = 0;
    m_expected_seqno = 0;
    m_next_recno_tx = 0;

    m_p_tir = nullptr;
    m_p_evp_cipher = nullptr;
    m_p_cipher_ctx = nullptr;
    m_next_recno_rx = 0;
    m_rx_offset = 0;
    m_rx_rec_len = 0;
    m_rx_rec_rcvd = 0;
    m_rx_sm = TLS_RX_SM_HEADER;
    m_refused_data = nullptr;
    m_rx_rule = nullptr;
    m_rx_psv_buf = nullptr;
    m_rx_resync_recno = 0;
}

sockinfo_tcp_ops_tls::~sockinfo_tcp_ops_tls()
{
    /* Destroy TLS object under TCP connection lock. */

    if (m_is_tls_tx) {
        m_p_tx_ring->tls_release_tis(m_p_tis);
        m_p_tis = nullptr;
        if (m_zc_stor) {
            /* Release references taken in advance, but not used. See get_record_buf(). */
            unsigned extra_ref = (m_zc_stor->sz_buffer - m_zc_stor_offset) / TLS_ZC_BLOCK;
            m_p_sock->get_tx_ring()->mem_buf_desc_return_single_multi_ref(m_zc_stor, extra_ref + 1);
            m_zc_stor = nullptr;
        }
    }
    if (m_is_tls_rx) {
        tcp_recv(m_p_sock->get_pcb(), sockinfo_tcp::rx_drop_lwip_cb);
        if (m_rx_rule) {
            delete m_rx_rule;
            m_rx_rule = nullptr;
        }
        m_p_tx_ring->tls_release_tir(m_p_tir);
        m_p_tir = nullptr;
        if (m_p_cipher_ctx) {
            g_tls_api->EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX *>(m_p_cipher_ctx));
            m_p_cipher_ctx = nullptr;
        }
        while (m_refused_data) {
            struct pbuf *p = m_refused_data;
            m_refused_data = p->next;
            p->next = nullptr;
            /* Free ZC buffers as RX buffers, further this is handled. */
            m_p_sock->tcp_rx_mem_buf_free(reinterpret_cast<mem_buf_desc_t *>(p));
        }
        if (!m_rx_bufs.empty()) {
            /*
             * The 1st buffer is special. We can have ZC buffers in the
             * TCP layer that point to it. To avoid reuse buffers list
             * corruption and similar mistakes, just reduce reference
             * counting for the 1st buffer if there are more than 1
             * users. Note, we are under TCP connection lock here.
             */
            mem_buf_desc_t *pdesc = m_rx_bufs.front();
            if (pdesc->lwip_pbuf.ref > 1) {
                m_rx_bufs.pop_front();
                pbuf_free(&pdesc->lwip_pbuf);
            }
            while (!m_rx_bufs.empty()) {
                pdesc = m_rx_bufs.get_and_pop_front();
                m_p_sock->tcp_rx_mem_buf_free(pdesc);
            }
        }
    }
}

void sockinfo_tcp_ops_tls::get_record_buf(mem_buf_desc_t *&buf, uint8_t *&data, bool is_zerocopy)
{
    if (!is_zerocopy) {
        buf = m_p_sock->tcp_tx_mem_buf_alloc(PBUF_RAM);
        if (buf) {
            data = buf->p_buffer;
        }
        return;
    }
    /*
     * Zerocopy path. We use a TX buffer to distribute 32 bytes blocks across multiple zerocopy
     * TLS records. In such a way we optimize buffers/memory usage (since zerocopy TLS record
     * requires 29 bytes to hold the header/trailer). Also this improves locality and MTT cache
     * miss rate.
     * Every block holds a reference to the TX buffer. We increase the reference counter in
     * advance to avoid additional locking.
     */
    if (!m_zc_stor) {
        m_zc_stor = m_p_sock->tcp_tx_mem_buf_alloc(PBUF_RAM);
        m_zc_stor_offset = 0;
        if (likely(m_zc_stor)) {
            m_zc_stor->lwip_pbuf.ref += m_zc_stor->sz_buffer / TLS_ZC_BLOCK;
        }
    }
    buf = m_zc_stor;
    if (m_zc_stor) {
        data = m_zc_stor->p_buffer + m_zc_stor_offset;
        m_zc_stor_offset += TLS_ZC_BLOCK;
        if (m_zc_stor_offset + TLS_ZC_BLOCK > m_zc_stor->sz_buffer) {
            m_p_sock->get_tx_ring()->mem_buf_desc_return_single_to_owner_tx(m_zc_stor);
            m_zc_stor = nullptr;
        }
    }
}

int sockinfo_tcp_ops_tls::setsockopt(int __level, int __optname, const void *__optval,
                                     socklen_t __optlen)
{
    uint64_t recno_be64;
    unsigned char *iv;
    unsigned char *salt;
    unsigned char *rec_seq;
    unsigned char *key;
    uint32_t keylen;
    const struct tls_crypto_info *base_info = (const struct tls_crypto_info *)__optval;

    if (__level != SOL_TLS) {
        return m_p_sock->tcp_setsockopt(__level, __optname, __optval, __optlen);
    }
    if (unlikely(__optname != TLS_TX && __optname != TLS_RX)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(__optlen < sizeof(tls12_crypto_info_aes_gcm_128) || !__optval)) {
        errno = EINVAL;
        return -1;
    }

    si_ulp_logdbg("TLS %s offload is requested", __optname == TLS_TX ? "TX" : "RX");

    if (unlikely(base_info->version != TLS_1_2_VERSION && base_info->version != TLS_1_3_VERSION)) {
        si_ulp_logdbg("Unsupported TLS version.");
        errno = ENOPROTOOPT;
        return -1;
    }

    if (__optname == TLS_TX) {
        /* TX offload checks. */
        if (unlikely(!m_p_sock->is_utls_supported(UTLS_MODE_TX))) {
            si_ulp_logdbg("TLS_TX is not supported.");
            errno = ENOPROTOOPT;
            return -1;
        }
    } else {
        /* RX offload checks. */
        if (unlikely(!m_p_sock->is_utls_supported(UTLS_MODE_RX))) {
            si_ulp_logdbg("TLS_RX is not supported.");
            errno = ENOPROTOOPT;
            return -1;
        }
        if (unlikely(!g_tls_api)) {
            si_ulp_logdbg("OpenSSL symbols aren't found, cannot support TLS RX offload.");
            errno = ENOPROTOOPT;
            return -1;
        }
        if (unlikely(!m_p_rx_ring)) {
            si_ulp_logdbg("Cannot determine RX ring, TLS RX offload is impossible.");
            errno = ENOPROTOOPT;
            return -1;
        }
        if (unlikely(m_p_tx_ring->get_ctx(0) != m_p_rx_ring->get_ctx(0))) {
            si_ulp_logdbg("TLS_RX doesn't support scenario where TX "
                          "and RX rings are on different IB contexts.");
            errno = ENOPROTOOPT;
            return -1;
        }
    }

    switch (base_info->cipher_type) {
    case TLS_CIPHER_AES_GCM_128:
        /* Wrap with a block to avoid initialization error */
        {
            struct tls12_crypto_info_aes_gcm_128 *crypto_info =
                (struct tls12_crypto_info_aes_gcm_128 *)__optval;
            iv = crypto_info->iv;
            salt = crypto_info->salt;
            rec_seq = crypto_info->rec_seq;
            key = crypto_info->key;
            keylen = TLS_CIPHER_AES_GCM_128_KEY_SIZE;
            if (__optname == TLS_RX) {
                m_p_evp_cipher = (void *)g_tls_api->EVP_aes_128_gcm();
            }
        }
        break;
#ifdef DEFINED_UTLS_AES256
    case TLS_CIPHER_AES_GCM_256:
        if (unlikely(__optlen < sizeof(tls12_crypto_info_aes_gcm_256))) {
            errno = EINVAL;
            return -1;
        }
        /* Wrap with a block to avoid initialization error */
        {
            struct tls12_crypto_info_aes_gcm_256 *crypto_info =
                (struct tls12_crypto_info_aes_gcm_256 *)__optval;
            iv = crypto_info->iv;
            salt = crypto_info->salt;
            rec_seq = crypto_info->rec_seq;
            key = crypto_info->key;
            keylen = TLS_CIPHER_AES_GCM_256_KEY_SIZE;
            if (__optname == TLS_RX) {
                m_p_evp_cipher = (void *)g_tls_api->EVP_aes_256_gcm();
            }
        }
        break;
#endif /* DEFINED_UTLS_AES256 */
    default:
        si_ulp_logdbg("Unsupported TLS cipher ID: %u.", base_info->cipher_type);
        errno = ENOPROTOOPT;
        return -1;
    }

    xlio_tls_info *tls_info = (__optname == TLS_TX) ? &m_tls_info_tx : &m_tls_info_rx;
    tls_info->tls_version = base_info->version;
    tls_info->tls_cipher = base_info->cipher_type;
    tls_info->key_len = keylen;
    memcpy(tls_info->key, key, keylen);
    memcpy(tls_info->iv, iv, TLS_AES_GCM_IV_LEN);
    memcpy(tls_info->salt, salt, TLS_AES_GCM_SALT_LEN);
    memcpy(tls_info->rec_seq, rec_seq, TLS_AES_GCM_REC_SEQ_LEN);
    memcpy(&recno_be64, rec_seq, TLS_AES_GCM_REC_SEQ_LEN);

    m_tls_rec_overhead =
        (base_info->version == TLS_1_2_VERSION) ? TLS_12_RECORD_OVERHEAD : TLS_13_RECORD_OVERHEAD;

    if (__optname == TLS_TX) {
        if (!m_p_tx_ring->credits_get(SQ_CREDITS_TLS_TX_CONTEXT)) {
            si_ulp_logdbg("No available space in SQ to create TLS TX context");
            errno = ENOPROTOOPT;
            return -1;
        }
        m_expected_seqno = m_p_sock->get_next_tcp_seqno();
        m_next_recno_tx = be64toh(recno_be64);
        m_p_tis = m_p_tx_ring->tls_context_setup_tx(&m_tls_info_tx);
        /* We don't need key for TX anymore. */
        memset(m_tls_info_tx.key, 0, keylen);
        if (unlikely(!m_p_tis)) {
            m_p_tx_ring->credits_return(SQ_CREDITS_TLS_TX_CONTEXT);
            errno = ENOPROTOOPT;
            return -1;
        }
        m_is_tls_tx = true;
        m_p_sock->get_sock_stats()->tls_tx_offload = true;
    } else {
        m_p_cipher_ctx = (void *)g_tls_api->EVP_CIPHER_CTX_new();
        if (unlikely(!m_p_cipher_ctx)) {
            si_ulp_logdbg("OpenSSL initialization failed.");
            errno = ENOPROTOOPT;
            return -1;
        }

        m_next_recno_rx = be64toh(recno_be64);
        m_is_tls_rx = true;

        /*
         * First, get TIR from the TX ring cache. Create new one in
         * the RX ring if the cache is empty.
         */
        m_p_tir = m_p_tx_ring->tls_create_tir(true) ?: m_p_rx_ring->tls_create_tir(false);

        m_p_sock->lock_tcp_con();
        if (m_p_tir) {
            err_t err = tls_rx_consume_ready_packets();
            if (unlikely(err != ERR_OK)) {
                si_ulp_logdbg("Cannot consume ready packets, TLS RX offload will likely fail.");
            }
        }

        if (m_p_tir) {
            uint32_t next_seqno_rx = m_p_sock->get_next_tcp_seqno_rx();
            int rc = -1;

            if (m_p_tx_ring->credits_get(SQ_CREDITS_TLS_RX_CONTEXT)) {
                rc = m_p_tx_ring->tls_context_setup_rx(m_p_tir, &m_tls_info_rx, next_seqno_rx,
                                                       &rx_comp_callback, this);
                if (unlikely(rc != 0)) {
                    m_p_tx_ring->credits_return(SQ_CREDITS_TLS_RX_CONTEXT);
                }
            } else {
                si_ulp_logdbg("No available space in SQ to create TLS RX context");
            }
            if (unlikely(rc != 0)) {
                m_p_tx_ring->tls_release_tir(m_p_tir);
                m_p_tir = nullptr;
            }
        }
        if (unlikely(!m_p_tir)) {
            si_ulp_logdbg("TLS RX offload setup failed");
            m_is_tls_rx = false;
            m_p_sock->unlock_tcp_con();
            errno = ENOPROTOOPT;
            return -1;
        }

        tcp_recv(m_p_sock->get_pcb(), sockinfo_tcp_ops_tls::rx_lwip_cb);
        m_p_sock->get_sock_stats()->tls_rx_offload = true;
        m_p_sock->unlock_tcp_con();
    }

    m_p_sock->get_sock_stats()->tls_version = base_info->version;
    m_p_sock->get_sock_stats()->tls_cipher = base_info->cipher_type;

    si_ulp_logdbg("TLS%s %s offload is configured, keylen=%u",
                  base_info->version == TLS_1_2_VERSION ? "1.2" : "1.3",
                  __optname == TLS_TX ? "TX" : "RX", keylen);
    return 0;
}

err_t sockinfo_tcp_ops_tls::tls_rx_consume_ready_packets()
{
    err_t ret = ERR_OK;

    /* Must be called under socket lock. */
    /*
     * If there are ready packets in the TCP socket's queue, we need to
     * process them through TLS SW engine, otherwise, application will
     * receive encrypted TLS records with header and TAG after successful
     * setsockopt() call.
     */
    if (m_p_sock->get_rx_pkt_ready_list_count() > 0) {
        descq_t descs_rx_ready;

        m_p_sock->sock_pop_descs_rx_ready(&descs_rx_ready);
        for (size_t i = 0; i < descs_rx_ready.size(); i++) {
            mem_buf_desc_t *temp;
            temp = descs_rx_ready.front();
            descs_rx_ready.pop_front();
            ret = recv(&temp->lwip_pbuf);
            if (unlikely(ERR_OK != ret)) {
                break;
            }
        }
        /* Update initial record number. */
        uint64_t recno_be64 = htobe64(m_next_recno_rx);
        memcpy(m_tls_info_rx.rec_seq, &recno_be64, TLS_AES_GCM_REC_SEQ_LEN);
    }
    return ret;
}

ssize_t sockinfo_tcp_ops_tls::tx(xlio_tx_call_attr_t &tx_arg)
{
    /*
     * TODO This method must be called under socket lock to avoid situation
     * where multiple send() are called simultaneously and multiple tls
     * records are associated with the same seqno (since pcb->snd_lbb isn't
     * updated).
     */

    xlio_tx_call_attr_t tls_arg;
    struct iovec *p_iov;
    struct iovec tls_iov[3]; /* 3 elements are for zerocopy case: header, payload and trailer. */
    uint64_t last_recno;
    ssize_t ret;
    size_t pos;
    int errno_save;
    bool block_this_run = BLOCK_THIS_RUN(m_p_sock->is_blocking(), tx_arg.attr.flags);
    bool is_zerocopy = tx_arg.attr.flags & MSG_ZEROCOPY;
    uint8_t tls_type = 0x17;

    if (!m_is_tls_tx) {
        return m_p_sock->tcp_tx(tx_arg);
    }

    errno_save = errno;

    tls_arg.opcode = TX_FILE; /* Not to use hugepage zerocopy path */
    tls_arg.attr.flags = MSG_ZEROCOPY;
    tls_arg.xlio_flags = TX_FLAG_NO_PARTIAL_WRITE;
    tls_arg.attr.iov = tls_iov;
    tls_arg.attr.sz_iov = is_zerocopy ? 3 : 1;
    tls_arg.priv.attr = PBUF_DESC_MDESC;

    p_iov = tx_arg.attr.iov;
    last_recno = m_next_recno_tx;
    ret = 0;

    /* Control sendmsg() support */
    if (tx_arg.opcode == TX_SENDMSG && tx_arg.attr.hdr) {
        struct msghdr *__msg = (struct msghdr *)tx_arg.attr.hdr;
        struct cmsghdr *cmsg;
        if (__msg->msg_controllen != 0) {
            for (cmsg = CMSG_FIRSTHDR(__msg); cmsg; cmsg = CMSG_NXTHDR(__msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_TLS && cmsg->cmsg_type == TLS_SET_RECORD_TYPE) {
                    tls_type = *CMSG_DATA(cmsg);
                }
            }
        }
    }

    uint8_t *iv = is_tx_tls13() ? nullptr : m_tls_info_tx.iv;
    mem_desc *zc_owner = is_zerocopy ? reinterpret_cast<mem_desc *>(tx_arg.priv.mdesc) : nullptr;
    for (ssize_t i = 0; i < tx_arg.attr.sz_iov; ++i) {
        pos = 0;
        while (pos < p_iov[i].iov_len) {
            tls_record *rec;
            ssize_t ret2;
            size_t tosend = std::min<size_t>(p_iov[i].iov_len - pos, TLS_RECORD_MAX);

            if (m_p_sock->sndbuf_available() == 0U && !block_this_run) {
                if (ret == 0) {
                    errno = EAGAIN;
                    ret = -1;
                }
                goto done;
            }

            rec =
                new tls_record(this, m_p_sock->get_next_tcp_seqno(), m_next_recno_tx, iv, zc_owner);
            if (unlikely(!rec || !rec->m_p_buf)) {
                if (ret == 0) {
                    errno = ENOMEM;
                    ret = -1;
                }
                if (rec) {
                    /* rec->put() is a right approach to destroy the record. However, clang-analyzer
                     * generates a false positive memory leak warning. Call destructor explicitly to
                     * suppress the warning.
                     */
                    delete rec;
                }
                goto done;
            }

            tosend = rec->append_data((uint8_t *)p_iov[i].iov_base + pos, tosend, is_tx_tls13());
            /* Set type after all data, because for TLS1.3 it is in the tail. */
            rec->set_type(tls_type, is_tx_tls13());
            rec->fill_iov(tls_arg.attr.iov, ARRAY_SIZE(tls_iov), is_tx_tls13());
            tls_arg.priv.mdesc = reinterpret_cast<void *>(rec);
            pos += tosend;

            ++m_next_recno_tx;
            /*
             * Prepare unique explicit_nonce for the next TLS1.2 record.
             * TLS1.3 always uses the initial IV.
             */
            if (!is_tx_tls13()) {
                ++m_tls_info_tx.iv64;
            }
        retry:
            if (!block_this_run) {
                ret2 = m_p_sock->tcp_tx_express(tls_arg.attr.iov, tls_arg.attr.sz_iov, 0,
                                                XLIO_EXPRESS_OP_TYPE_FILE_ZEROCOPY,
                                                reinterpret_cast<void *>(rec));

            } else {
                ret2 = m_p_sock->tcp_tx(tls_arg);
            }
            if (block_this_run && (ret2 != (ssize_t)tls_arg.attr.iov[0].iov_len)) {
                if ((ret2 >= 0) || (errno == EINTR && !g_b_exit)) {
                    ret2 = ret2 < 0 ? 0 : ret2;
                    tls_arg.attr.iov[0].iov_len -= ret2;
                    tls_arg.attr.iov[0].iov_base =
                        (void *)((uint8_t *)tls_arg.attr.iov[0].iov_base + ret2);
                    goto retry;
                }
                if (tls_arg.attr.iov[0].iov_len != rec->m_size) {
                    /* We cannot recover from a fail in the middle of a TLS record */
                    if (!g_b_exit) {
                        m_p_sock->abort_connection();
                    }
                    ret += (rec->m_size - tls_arg.attr.iov[0].iov_len);
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
                --m_next_recno_tx;
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
        if (unlikely(m_p_sock->has_stats())) {
            m_p_sock->get_sock_stats()->tls_counters.n_tls_tx_records +=
                m_next_recno_tx - last_recno;
            m_p_sock->get_sock_stats()->tls_counters.n_tls_tx_bytes += ret;
        }
    }
    return ret;
}

int sockinfo_tcp_ops_tls::postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr)
{
    if (m_is_tls_tx && seg && p->type != PBUF_RAM) {
        if (seg->len != 0) {
            if (unlikely(seg->seqno != m_expected_seqno)) {

                /* For zerocopy the 1st pbuf is always a TCP header and the pbuf is on stack */
                assert(p->type == PBUF_STACK); /* TCP header pbuf */
                assert(p->next && p->next->desc.attr == PBUF_DESC_MDESC);
                tls_record *rec = dynamic_cast<tls_record *>((mem_desc *)p->next->desc.mdesc);
                if (unlikely(!rec)) {
                    return ERR_RTE;
                }

                si_ulp_logdbg("TX resync flow: record_number=%lu seqno%u", rec->m_record_number,
                              seg->seqno);

                uint8_t *addr = rec->m_p_data;
                uint64_t recno_be64 = htobe64(rec->m_record_number);
                bool skip_static =
                    !memcmp(m_tls_info_tx.rec_seq, &recno_be64, TLS_AES_GCM_REC_SEQ_LEN);
                bool is_zerocopy = rec->m_p_zc_owner;
                unsigned mss = m_p_sock->get_mss();
                uint32_t totlen = seg->seqno - rec->m_seqno;
                uint32_t lkey = LKEY_TX_DEFAULT;
                uint32_t hdrlen = 0;
                uint32_t taillen = 0;

                if (is_zerocopy) {
                    hdrlen = std::min<uint32_t>(
                        TLS_RECORD_HDR_LEN +
                            (is_tx_tls13() ? TLS_13_RECORD_IV_LEN : TLS_RECORD_IV_LEN),
                        totlen);
                    taillen = TLS_RECORD_TAG_LEN + !!is_tx_tls13();
                    /* Determine the trailer portion to resend. */
                    taillen = std::max<uint32_t>(totlen + taillen, rec->m_size) - rec->m_size;
                }

                /*
                 * Request precise number of credits for DUMP WQEs and UMR/SET_PSV WQEs:
                 *
                 * - Number of DUMP WQEs:
                 *   DUMP WQEs don't support TSO, therefore, we send data in MSS length blocks.
                 *   For zerocopy case we send header and trailer in separated WQEs, because
                 *   they're not contiguous with the payload.
                 *
                 * - Credits formula:
                 *   Resync contains from optional UMR, SET_PSV, multiple DUMP WQEs. If there
                 *   are no DUMP WQEs (resync happens at the beginning of a TLS record) we need
                 *   to post a single NOP WQE.
                 *
                 * TODO Send DUMP WQEs in MTU length blocks instead of MSS.
                 */
                unsigned dump_nr =
                    (totlen - hdrlen - taillen + mss - 1) / mss + (hdrlen != 0) + (taillen != 0);
                unsigned credits = SQ_CREDITS_SET_PSV + !skip_static * SQ_CREDITS_UMR +
                    dump_nr * SQ_CREDITS_DUMP + !dump_nr * SQ_CREDITS_NOP;
                si_ulp_logdbg("TX resync flow: requesting %u credits to resync %" PRIu32 " bytes",
                              credits, totlen);
                if (!m_p_tx_ring->credits_get(credits)) {
                    si_ulp_logdbg("TX resync flow: no available %u credits in SQ", credits);
                    return ERR_WOULDBLOCK;
                }

                if (!skip_static) {
                    memcpy(m_tls_info_tx.rec_seq, &recno_be64, TLS_AES_GCM_REC_SEQ_LEN);
                }
                m_p_tx_ring->tls_context_resync_tx(&m_tls_info_tx, m_p_tis, skip_static);

                if (totlen == 0) {
                    m_p_tx_ring->post_nop_fence();
                } else {
                    bool b_fence = true;
                    uint8_t *addr_tail;

                    if (is_zerocopy) {
                        /* hdrlen and taillen are prepared above. */
                        m_p_tx_ring->tls_tx_post_dump_wqe(m_p_tis, (void *)addr, hdrlen,
                                                          LKEY_TX_DEFAULT, true);
                        addr_tail = addr + hdrlen;
                        addr = rec->m_p_zc_data;
                        totlen = totlen - hdrlen - taillen; /* Remaining ZC part. */
                        lkey = rec->get_lkey(reinterpret_cast<mem_buf_desc_t *>(p),
                                             m_p_sock->get_ctx(), addr, totlen);
                        b_fence = false;
                        --dump_nr;
                    }

                    while (totlen > 0) {
                        uint32_t len = std::min(totlen, mss);
                        m_p_tx_ring->tls_tx_post_dump_wqe(m_p_tis, (void *)addr, len, lkey,
                                                          b_fence);
                        totlen -= len;
                        addr += len;
                        b_fence = false;
                        --dump_nr;
                    }

                    if (is_zerocopy && taillen) {
                        m_p_tx_ring->tls_tx_post_dump_wqe(m_p_tis, (void *)addr_tail, taillen,
                                                          LKEY_TX_DEFAULT, false);
                        --dump_nr;
                    }
                }

                assert(dump_nr == 0);
                NOT_IN_USE(dump_nr);
                m_expected_seqno = seg->seqno;

                /* Statistics */
                ++m_p_sock->get_sock_stats()->tls_counters.n_tls_tx_resync;
                m_p_sock->get_sock_stats()->tls_counters.n_tls_tx_resync_replay +=
                    (seg->seqno != rec->m_seqno);
            }
            m_expected_seqno += seg->len;
            attr.tis = m_p_tis;
        }
    }
    return 0;
}

bool sockinfo_tcp_ops_tls::handle_send_ret(ssize_t ret, struct tcp_seg *seg)
{
    if (ret < 0 && seg) {
        m_expected_seqno -= seg->len;
        return false;
    }

    return true;
}

int sockinfo_tcp_ops_tls::send_alert(uint8_t alert_type)
{
    unsigned char record_type = TLS_ALERT;
    struct msghdr msg = {};
    struct cmsghdr *cmsg;
    uint8_t buf[CMSG_SPACE(sizeof(record_type))];
    struct iovec msg_iov;

    if (!m_is_tls_tx) {
        /*
         * We reuse TLS TX offload functionality to build and encrypt
         * TLS record. Currently we don't support manual alert record
         * construction.
         */
        return -1;
    }

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_TLS;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(sizeof(record_type));
    *CMSG_DATA(cmsg) = record_type;
    msg.msg_controllen = cmsg->cmsg_len;

    uint8_t alert[2] = {alert_type, get_alert_level(alert_type)};
    msg_iov.iov_base = alert;
    msg_iov.iov_len = sizeof(alert);
    msg.msg_iov = &msg_iov;
    msg.msg_iovlen = 1;

    /* Send alert through TLS offloaded sendmsg() path. */
    xlio_tx_call_attr_t tx_arg;
    tx_arg.opcode = TX_SENDMSG;
    tx_arg.attr.iov = msg.msg_iov;
    tx_arg.attr.sz_iov = (ssize_t)msg.msg_iovlen;
    tx_arg.attr.flags = 0;
    tx_arg.attr.hdr = &msg;
    ssize_t ret = tx(tx_arg);

    return ret > 0 ? 0 : -1;
}

void sockinfo_tcp_ops_tls::terminate_session_fatal(uint8_t alert_type)
{
    (void)send_alert(alert_type);
    m_p_sock->tcp_shutdown_rx();
    m_rx_sm = TLS_RX_SM_FAIL;
}

void sockinfo_tcp_ops_tls::copy_by_offset(uint8_t *dst, uint32_t offset, uint32_t len)
{
    auto iter = m_rx_bufs.begin();
    mem_buf_desc_t *pdesc = *iter;

    /* Skip leading buffers */
    if (unlikely(pdesc->lwip_pbuf.len <= offset)) {
        while (pdesc && pdesc->lwip_pbuf.len <= offset) {
            offset -= pdesc->lwip_pbuf.len;
            pdesc = *(++iter);
        }
    }

    /* Copy */
    while (likely(pdesc) && len > 0) {
        uint32_t buflen = std::min<uint32_t>(pdesc->lwip_pbuf.len - offset, len);

        memcpy(dst, (uint8_t *)pdesc->lwip_pbuf.payload + offset, buflen);
        len -= buflen;
        dst += buflen;
        offset = 0;

        pdesc = *(++iter);
    }
}

/* More efficient method to get 16bit value in the buffer list. */
uint16_t sockinfo_tcp_ops_tls::offset_to_host16(uint32_t offset)
{
    auto iter = m_rx_bufs.begin();
    mem_buf_desc_t *pdesc = *iter;
    uint16_t res = 0;

    /* Skip leading buffers */
    if (unlikely(pdesc->lwip_pbuf.len <= offset)) {
        while (pdesc && pdesc->lwip_pbuf.len <= offset) {
            offset -= pdesc->lwip_pbuf.len;
            pdesc = *(++iter);
        }
    }

    if (likely(pdesc)) {
        res = (uint16_t)((uint8_t *)pdesc->lwip_pbuf.payload)[offset] << 8U;
        ++offset;
        if (unlikely(offset >= pdesc->lwip_pbuf.len)) {
            offset = 0;
            pdesc = *(++iter);
            if (unlikely(!pdesc)) {
                return 0;
            }
        }
        res |= (uint16_t)((uint8_t *)pdesc->lwip_pbuf.payload)[offset];
    }
    return res;
}

int sockinfo_tcp_ops_tls::tls_rx_decrypt(struct pbuf *plist)
{
    /* Multi-purpose buffer, TAG is the largest object. */
    uint8_t buf[TLS_RECORD_TAG_LEN] __attribute__((aligned(8)));
    EVP_CIPHER_CTX *tls_ctx;
    struct pbuf *p;
    int len;
    int ret;

    tls_ctx = (EVP_CIPHER_CTX *)m_p_cipher_ctx;
    assert(tls_ctx);
    ret = g_tls_api->EVP_CIPHER_CTX_reset(tls_ctx);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Build nonce. */
    memcpy(buf, m_tls_info_rx.salt, TLS_AES_GCM_SALT_LEN);
    if (is_rx_tls13()) {
        uint64_t iv64 = m_tls_info_rx.iv64;
        iv64 ^= htobe64(m_next_recno_rx);
        memcpy(&buf[TLS_AES_GCM_SALT_LEN], &iv64, sizeof(iv64));
    } else {
        copy_by_offset(&buf[TLS_AES_GCM_SALT_LEN], m_rx_offset + TLS_RECORD_HDR_LEN,
                       TLS_RECORD_IV_LEN);
    }
    ret = g_tls_api->EVP_DecryptInit_ex(tls_ctx, (EVP_CIPHER *)m_p_evp_cipher, nullptr,
                                        m_tls_info_rx.key, buf);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Set authentication tag. TODO We can avoid copy if the tag doesn't cross a pbuf boundary. */
    copy_by_offset(buf, m_rx_offset + m_rx_rec_len - TLS_RECORD_TAG_LEN, TLS_RECORD_TAG_LEN);
    ret = g_tls_api->EVP_CIPHER_CTX_ctrl(tls_ctx, EVP_CTRL_GCM_SET_TAG, TLS_RECORD_TAG_LEN, buf);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Additional data for AEAD */
    if (is_rx_tls13()) {
        uint16_t rec_len = m_rx_rec_len - TLS_RECORD_HDR_LEN;
        copy_by_offset(buf, m_rx_offset, 3);
        buf[3] = rec_len >> 8U;
        buf[4] = rec_len & 0xFFU;
        ret = g_tls_api->EVP_DecryptUpdate(tls_ctx, nullptr, &len, buf, 5);
    } else {
        uint16_t rec_len = m_rx_rec_len - m_tls_rec_overhead;
        *((uint64_t *)buf) = htobe64(m_next_recno_rx);
        copy_by_offset(buf + 8, m_rx_offset, 3);
        buf[11] = rec_len >> 8U;
        buf[12] = rec_len & 0xFFU;
        ret = g_tls_api->EVP_DecryptUpdate(tls_ctx, nullptr, &len, buf, 13);
    }
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    for (p = plist; p; p = p->next) {
        if (((mem_buf_desc_t *)p)->rx.tls_decrypted == TLS_RX_DECRYPTED) {
            /*
             * This is partially decrypted record, stop here
             * and don't verify authentication tag.
             */
            return 0;
        }
        ret = g_tls_api->EVP_DecryptUpdate(tls_ctx, (uint8_t *)p->payload, &len,
                                           (uint8_t *)p->payload, p->len);
        /* XXX Can AES-GCM return len != p->len if not aligned to blocksize? */
        if (unlikely(!ret || len != (int)p->len)) {
            return TLS_DECRYPT_INTERNAL;
        }
        ((mem_buf_desc_t *)p)->rx.tls_decrypted = TLS_RX_DECRYPTED;
    }

    ret = g_tls_api->EVP_DecryptFinal_ex(tls_ctx, buf /* XXX */, &len);
    if (unlikely(!ret || len != 0)) {
        return ret ? TLS_DECRYPT_INTERNAL : TLS_DECRYPT_BAD_MAC;
    }
    return 0;
}

int sockinfo_tcp_ops_tls::tls_rx_encrypt(struct pbuf *plist)
{
    /* Multi-purpose buffer, TAG is the largest object. */
    uint8_t buf[TLS_RECORD_TAG_LEN] __attribute__((aligned(8)));
    EVP_CIPHER_CTX *tls_ctx;
    struct pbuf *p;
    uint16_t rec_len = m_rx_rec_len - m_tls_rec_overhead;
    int len;
    int ret;

    tls_ctx = (EVP_CIPHER_CTX *)m_p_cipher_ctx;
    assert(tls_ctx);
    ret = g_tls_api->EVP_CIPHER_CTX_reset(tls_ctx);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Build nonce. */
    memcpy(buf, m_tls_info_rx.salt, TLS_AES_GCM_SALT_LEN);
    if (is_rx_tls13()) {
        uint64_t iv64 = m_tls_info_rx.iv64;
        iv64 ^= htobe64(m_next_recno_rx);
        memcpy(&buf[TLS_AES_GCM_SALT_LEN], &iv64, sizeof(iv64));
    } else {
        copy_by_offset(&buf[TLS_AES_GCM_SALT_LEN], m_rx_offset + TLS_RECORD_HDR_LEN,
                       TLS_RECORD_IV_LEN);
    }
    ret = g_tls_api->EVP_EncryptInit_ex(tls_ctx, (EVP_CIPHER *)m_p_evp_cipher, nullptr,
                                        m_tls_info_rx.key, buf);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Set authentication tag. TODO We can avoid copy if the tag doesn't cross a pbuf boundary. */
    copy_by_offset(buf, m_rx_offset + m_rx_rec_len - TLS_RECORD_TAG_LEN, TLS_RECORD_TAG_LEN);
    ret = g_tls_api->EVP_CIPHER_CTX_ctrl(tls_ctx, EVP_CTRL_GCM_SET_TAG, TLS_RECORD_TAG_LEN, buf);
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    /* Additional data for AEAD */
    if (is_rx_tls13()) {
        copy_by_offset(buf, m_rx_offset, 3);
        buf[3] = rec_len >> 8U;
        buf[4] = rec_len & 0xFFU;
        ret = g_tls_api->EVP_EncryptUpdate(tls_ctx, nullptr, &len, buf, 5);
    } else {
        *((uint64_t *)buf) = htobe64(m_next_recno_rx);
        copy_by_offset(buf + 8, m_rx_offset, 3);
        buf[11] = rec_len >> 8U;
        buf[12] = rec_len & 0xFFU;
        ret = g_tls_api->EVP_EncryptUpdate(tls_ctx, nullptr, &len, buf, 13);
    }
    if (unlikely(!ret)) {
        return TLS_DECRYPT_INTERNAL;
    }

    for (p = plist; p; p = p->next) {
        if (((mem_buf_desc_t *)p)->rx.tls_decrypted != TLS_RX_DECRYPTED) {
            /* This is partially encrypted record, stop here. */
            return 0;
        }
        ret = g_tls_api->EVP_EncryptUpdate(tls_ctx, (uint8_t *)p->payload, &len,
                                           (uint8_t *)p->payload, p->len);
        /* XXX Can AES-GCM return len != p->len if not aligned to blocksize? */
        if (unlikely(!ret || len != (int)p->len)) {
            return TLS_DECRYPT_INTERNAL;
        }
        ((mem_buf_desc_t *)p)->rx.tls_decrypted = TLS_RX_ENCRYPTED;
    }

    ret = g_tls_api->EVP_EncryptFinal_ex(tls_ctx, buf /* XXX */, &len);
    if (unlikely(!ret || len != 0)) {
        return ret ? TLS_DECRYPT_INTERNAL : TLS_DECRYPT_BAD_MAC;
    }
    return 0;
}

err_t sockinfo_tcp_ops_tls::recv(struct pbuf *p)
{
    bool resync_requested = false;
    err_t err;

    if (m_rx_bufs.empty()) {
        m_rx_offset = 0;
    }

    m_rx_rec_rcvd += p->tot_len;
    while (p) {
        mem_buf_desc_t *pdesc = reinterpret_cast<mem_buf_desc_t *>(p);
        struct pbuf *ptmp = p->next;

        if (unlikely(pdesc->rx.tls_decrypted == TLS_RX_RESYNC)) {
            resync_requested = true;
        }
        pdesc->rx.n_frags = 1;
        p->tot_len = p->len;
        p->next = nullptr;
        m_rx_bufs.push_back(pdesc);
        p = ptmp;
    }

    if (unlikely(resync_requested && !m_rx_psv_buf) &&
        m_p_tx_ring->credits_get(SQ_CREDITS_TLS_RX_GET_PSV)) {
        /* If we fail to request credits we will retry resync flow with the next incoming packet. */
        m_rx_psv_buf = m_p_sock->tcp_tx_mem_buf_alloc(PBUF_RAM);
        m_rx_psv_buf->lwip_pbuf.payload =
            (void *)(((uintptr_t)m_rx_psv_buf->p_buffer + 63U) >> 6U << 6U);
        uint8_t *payload = (uint8_t *)m_rx_psv_buf->lwip_pbuf.payload;
        if (likely(m_rx_psv_buf->sz_buffer >= (size_t)(payload - m_rx_psv_buf->p_buffer + 64))) {
            memset(m_rx_psv_buf->lwip_pbuf.payload, 0, 64);
            m_rx_resync_recno = m_next_recno_rx;
            m_p_tx_ring->tls_get_progress_params_rx(m_p_tir, payload, LKEY_TX_DEFAULT);
            ++m_p_sock->get_sock_stats()->tls_counters.n_tls_rx_resync;
        }
    }

    if (unlikely(m_refused_data)) {
        err =
            sockinfo_tcp::rx_lwip_cb((void *)m_p_sock, m_p_sock->get_pcb(), m_refused_data, ERR_OK);
        if (unlikely(err != ERR_OK)) {
            /*
             * We queue all incoming packets and never return an error.
             * If application stops reading the data we expect to queue
             * not more than the TCP receive window.
             */
            return ERR_OK;
        }
        m_refused_data = nullptr;
    }

check_single_record:

    if (m_rx_sm == TLS_RX_SM_HEADER && m_rx_rec_rcvd >= TLS_RECORD_HDR_LEN) {
        m_rx_rec_len = offset_to_host16(m_rx_offset + 3) + TLS_RECORD_HDR_LEN;
        m_rx_sm = TLS_RX_SM_RECORD;
        if (unlikely(offset_to_host16(m_rx_offset + 1) != 0x0303U)) {
            terminate_session_fatal(TLS_PROTOCOL_VERSION);
            return ERR_OK;
        }
        if (unlikely(m_rx_rec_len < m_tls_rec_overhead)) {
            terminate_session_fatal(TLS_UNEXPECTED_MESSAGE);
            return ERR_OK;
        }
    }

    if (m_rx_sm != TLS_RX_SM_RECORD || m_rx_rec_rcvd < m_rx_rec_len) {
        return ERR_OK;
    }

    /* The first record is complete - push the payload to application. */

    auto iter = m_rx_bufs.begin();
    struct pbuf *pi;
    struct pbuf *pres = nullptr;
    struct pbuf *ptmp = nullptr;
    uint32_t offset = m_rx_offset + TLS_RECORD_HDR_LEN +
        (is_rx_tls13() ? TLS_13_RECORD_IV_LEN : TLS_RECORD_IV_LEN);
    uint32_t remain = m_rx_rec_len - m_tls_rec_overhead;
    unsigned bufs_nr = 0;
    unsigned decrypted_nr = 0;
    uint8_t tls_type;
    uint8_t tls_decrypted = 0;

    mem_buf_desc_t *pdesc = *iter;
    tls_type = ((uint8_t *)pdesc->lwip_pbuf.payload)[m_rx_offset];
    if (is_rx_tls13()) {
        /* TLS 1.3 sends record type as the last byte of the payload. */
        ++remain;
        if (unlikely(tls_type != 0x17)) {
            terminate_session_fatal(TLS_UNEXPECTED_MESSAGE);
            return ERR_OK;
        }
    }
    while (remain > 0) {
        if (unlikely(!pdesc)) {
            /* TODO Handle this situation, buffers chain is broken. */
            break;
        }

        pi = &pdesc->lwip_pbuf;
        if (pi->len <= offset) {
            offset -= pi->len;
            goto next_buffer;
        }

        ptmp =
            sockinfo_tcp::tcp_tx_pbuf_alloc(m_p_sock->get_pcb(), PBUF_ZEROCOPY, nullptr, nullptr);
        ptmp->len = ptmp->tot_len = std::min<uint32_t>(pi->len - offset, remain);
        ptmp->payload = (void *)((uint8_t *)pi->payload + offset);
        ptmp->next = nullptr;
        ((mem_buf_desc_t *)ptmp)->p_next_desc = nullptr;
        ((mem_buf_desc_t *)ptmp)->p_prev_desc = nullptr;
        ((mem_buf_desc_t *)ptmp)->m_flags = 0;
        ((mem_buf_desc_t *)ptmp)->rx.tls_type = tls_type;
        tls_decrypted = ((mem_buf_desc_t *)pi)->rx.tls_decrypted;
        ((mem_buf_desc_t *)ptmp)->rx.tls_decrypted = tls_decrypted;

        ++bufs_nr;
        decrypted_nr += !!(tls_decrypted == TLS_RX_DECRYPTED);

        if (!pres) {
            pres = ptmp;
        } else {
            /* XXX Complexity of building pres list is O(N^2). */
            pbuf_cat(pres, ptmp);
        }

        /* Reference counting for the underlying buffer. TODO Refactor. */
        ++pi->ref;
        ptmp->desc.attr = PBUF_DESC_TLS_RX;
        ptmp->desc.mdesc = (void *)pi;

        remain -= ptmp->len;
        offset = 0;

    next_buffer:
        pdesc = *(++iter);
    }

    int ret = 0;
    if (bufs_nr != decrypted_nr) {
        /*
         * tls_decrypted holds value for the last buffer.
         *
         * There are multiple possible scenarios:
         * 1. Authentication failed (tls_decrypted == TLS_RX_AUTH_FAIL)
         * 2. E E E E - full record is encrypted
         * 3. E D D D - the 1st buffer is encrypted, authentication passed
         * 4. D D E E - tail is encrypted, authentication not checked
         * 5. E D E E - decrypted buffers in the middle
         */

        if (decrypted_nr == 0 || tls_decrypted == TLS_RX_DECRYPTED) {
            /* Case #2 and #3. */
            ret = tls_rx_decrypt(pres);
        } else if (tls_decrypted == TLS_RX_AUTH_FAIL) {
            /* Case #1. */
            ret = TLS_DECRYPT_BAD_MAC;
        } else {
            /* Case #4 and #5. */
            switch (((mem_buf_desc_t *)pres)->rx.tls_decrypted) {
            case TLS_RX_RESYNC:
                /* Fallthrough */
            case TLS_RX_ENCRYPTED:
                ret = tls_rx_decrypt(pres);
                /* Fallthrough */
            case TLS_RX_DECRYPTED:
                ret = ret ?: tls_rx_encrypt(pres) ?: tls_rx_decrypt(pres);
                break;
            default:
                /* Unexpected case. */
                assert(0);
                break;
            }
        }

        /* Statistics */
        if (unlikely(m_p_sock->has_stats())) {
            m_p_sock->get_sock_stats()->tls_counters.n_tls_rx_records_enc += !!(decrypted_nr == 0);
            m_p_sock->get_sock_stats()->tls_counters.n_tls_rx_records_partial +=
                !!(decrypted_nr != 0);
        }
    }

    /* Handle decryption failures. */
    if (unlikely(ret != 0)) {
        terminate_session_fatal(ret == TLS_DECRYPT_BAD_MAC ? TLS_BAD_RECORD_MAC
                                                           : TLS_INTERNAL_ERROR);
        m_refused_data = pres;
        return ERR_OK;
    }

    if (is_rx_tls13() && likely(ptmp)) {
        /* ptmp is the last buffer in 'pres' list at this point. */
        tls_type = ((uint8_t *)ptmp->payload)[ptmp->len - 1];
        --ptmp->len;
        if (unlikely(ptmp->len == 0)) {
            ptmp = pres;
            while (ptmp && ptmp->next) {
                if (ptmp->next->len == 0) {
                    m_p_sock->tcp_rx_mem_buf_free(reinterpret_cast<mem_buf_desc_t *>(ptmp->next));
                    ptmp->next = nullptr;
                }
                ptmp = ptmp->next;
            }
        }
        for (ptmp = pres; ptmp; ptmp = ptmp->next) {
            --ptmp->tot_len;
            ((mem_buf_desc_t *)ptmp)->rx.tls_type = tls_type;
        }
    }

    /* Statistics */
    if (unlikely(m_p_sock->has_stats())) {
        m_p_sock->get_sock_stats()->tls_counters.n_tls_rx_records += 1U;
        m_p_sock->get_sock_stats()->tls_counters.n_tls_rx_bytes += likely(pres) ? pres->tot_len : 0;
        /* Adjust TCP counters with received TLS header/trailer. */
        m_p_sock->get_sock_stats()->counters.n_rx_bytes += m_tls_rec_overhead;
    }

    ++m_next_recno_rx;

    tcp_recved(m_p_sock->get_pcb(), m_tls_rec_overhead);
    if (likely(pres)) {
        assert(pres->tot_len == (m_rx_rec_len - m_tls_rec_overhead));
        err = sockinfo_tcp::rx_lwip_cb((void *)m_p_sock, m_p_sock->get_pcb(), pres, ERR_OK);
        if (err != ERR_OK) {
            /* Underlying buffers are held by 'pres', we can free them below. */
            m_refused_data = pres;
        }
    }

    /* Free received underlying buffers. */

    while (m_rx_rec_len > 0) {
        if (unlikely(m_rx_bufs.empty())) {
            /* TODO Handle broken buffers chain. */
            pdesc = nullptr;
            break;
        }
        pdesc = m_rx_bufs.front();
        if (pdesc->lwip_pbuf.len > (m_rx_rec_len + m_rx_offset)) {
            break;
        }
        m_rx_bufs.pop_front();
        m_rx_rec_len -= pdesc->lwip_pbuf.len - m_rx_offset;
        m_rx_rec_rcvd -= pdesc->lwip_pbuf.len - m_rx_offset;
        m_rx_offset = 0;
        /*
         * pbuf_free() is slow when it actually frees a buffer, however,
         * we expect to only reduce ref counter with this call.
         */
        pbuf_free(&pdesc->lwip_pbuf);
    }
    m_rx_offset += m_rx_rec_len;
    m_rx_rec_rcvd -= m_rx_rec_len;

    m_rx_sm = TLS_RX_SM_HEADER;
    if (pdesc && err == ERR_OK) {
        /* Check for other complete records in the last buffer. */
        goto check_single_record;
    }
    return ERR_OK;
}

/* static */
err_t sockinfo_tcp_ops_tls::rx_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    sockinfo_tcp *conn = (sockinfo_tcp *)arg;
    sockinfo_tcp_ops *ops = conn->get_ops();

    if (likely(p && err == ERR_OK)) {
        return ops->recv(p);
    }
    return sockinfo_tcp::rx_lwip_cb(arg, tpcb, p, err);
}

uint64_t sockinfo_tcp_ops_tls::find_recno(uint32_t seqno)
{
    /*
     * TODO Find proper record number for specific seqno.
     * Current implementation is a speculation. We need to track TCP seqno
     * of TLS records to provide correct record number and verify that the
     * seqno points to a TLS header.
     */
    NOT_IN_USE(seqno);
    return m_rx_resync_recno;
}

/* static */
void sockinfo_tcp_ops_tls::rx_comp_callback(void *arg)
{
    sockinfo_tcp_ops_tls *utls = reinterpret_cast<sockinfo_tcp_ops_tls *>(arg);

    if (utls->m_rx_psv_buf) {
        /* Resync flow, GET_PSV is completed. */
        struct xlio_tls_progress_params *params =
            (struct xlio_tls_progress_params *)utls->m_rx_psv_buf->lwip_pbuf.payload;
        uint32_t resync_seqno = be32toh(params->hw_resync_tcp_sn);
        int tracker = params->state >> 6U;
        int auth = (params->state >> 4U) & 0x3U;
        if (tracker == TLS_TRACKER_TRACKING && auth == TLS_AUTH_NO_OFFLOAD) {
            if (utls->m_p_tx_ring->credits_get(SQ_CREDITS_TLS_RX_RESYNC)) {
                uint64_t recno_be64 = htobe64(utls->find_recno(resync_seqno));
                memcpy(utls->m_tls_info_rx.rec_seq, &recno_be64, TLS_AES_GCM_REC_SEQ_LEN);
                utls->m_p_tx_ring->tls_resync_rx(utls->m_p_tir, &utls->m_tls_info_rx, resync_seqno);
            } else {
                /* We will retry RX resync with the next incoming packet. */
                vlog_printf(VLOG_DEBUG, "Skip TLS RX resync due to full SQ\n");
            }
        } else {
            /* TODO Investigate this case. It isn't described in PRM. */
        }
        utls->m_p_tx_ring->mem_buf_desc_return_single_to_owner_tx(utls->m_rx_psv_buf);
        utls->m_rx_psv_buf = nullptr;
    } else if (!utls->m_rx_rule) {
        /* Initial setup flow. */
        const flow_tuple_with_local_if &tuple = utls->m_p_sock->get_flow_tuple();
        utls->m_rx_rule = utls->m_p_rx_ring->tls_rx_create_rule(tuple, utls->m_p_tir);
        if (!utls->m_rx_rule) {
            vlog_printf(VLOG_ERROR, "TLS rule failed for %s\n", tuple.to_str().c_str());
        }
    }
}
#endif /* DEFINED_UTLS */
