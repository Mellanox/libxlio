/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef _SOCKINFO_ULP_H
#define _SOCKINFO_ULP_H

#include "sockinfo.h" /* xlio_tx_call_attr_t */
#include "proto/dst_entry.h" /* xlio_send_attr */
#include "proto/tls.h" /* xlio_tls_info */
#include "lwip/err.h" /* err_t */

#include <stdint.h>

/*
 * TODO Make ULP layer generic (not TCP specific) and implement ULP manager.
 */

/* Forward declarations */
class sockinfo_tcp;
class xlio_tis;
struct pbuf;

class sockinfo_tcp_ops {
public:
    sockinfo_tcp_ops(sockinfo_tcp *sock)
        : m_p_sock(sock) {};
    virtual ~sockinfo_tcp_ops() = default;

    inline ring *get_tx_ring();

    virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
    virtual ssize_t tx(xlio_tx_call_attr_t &tx_arg);
    virtual int postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr);
    virtual bool handle_send_ret(uint32_t ret, struct tcp_seg *seg);

    virtual err_t recv(struct pbuf *p)
    {
        NOT_IN_USE(p);
        return ERR_OK;
    };

protected:
    sockinfo_tcp *const m_p_sock;
};

#ifdef DEFINED_UTLS

enum xlio_utls_mode {
    UTLS_MODE_TX = 1 << 0,
    UTLS_MODE_RX = 1 << 1,
};

void xlio_tls_api_setup();

class sockinfo_tcp_ops_tls : public sockinfo_tcp_ops {
public:
    sockinfo_tcp_ops_tls(sockinfo_tcp *sock);
    ~sockinfo_tcp_ops_tls() override;

    int setsockopt(int, int, const void *, socklen_t) override;
    ssize_t tx(xlio_tx_call_attr_t &tx_arg) override;
    int postrouting(struct pbuf *p, struct tcp_seg *seg, xlio_send_attr &attr) override;
    bool handle_send_ret(uint32_t ret, struct tcp_seg *seg) override;

    void get_record_buf(mem_buf_desc_t *&buf, uint8_t *&data, bool is_zerocopy);

private:
    inline bool is_tx_tls13() { return m_tls_info_tx.tls_version == TLS_1_3_VERSION; }
    inline bool is_rx_tls13() { return m_tls_info_rx.tls_version == TLS_1_3_VERSION; }

    int send_alert(uint8_t alert_type);
    void terminate_session_fatal(uint8_t alert_type);

    err_t tls_rx_consume_ready_packets();
    err_t recv(struct pbuf *p) override;
    void copy_by_offset(uint8_t *dst, uint32_t offset, uint32_t len);
    uint16_t offset_to_host16(uint32_t offset);
    int tls_rx_decrypt(struct pbuf *plist);
    int tls_rx_encrypt(struct pbuf *plist);

    uint64_t find_recno(uint32_t seqno);

    static err_t rx_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    static void rx_comp_callback(void *arg);

    enum tls_rx_state {
        TLS_RX_SM_UNKNOWN = 0,
        /* Initial state. The header of the first record is incomplete. */
        TLS_RX_SM_HEADER,
        /* The first unhandled record is incomplete. */
        TLS_RX_SM_RECORD,
        /* Terminal state when decryption/authentication fails. */
        TLS_RX_SM_FAIL,
    };

    enum tls_decrypt_error {
        TLS_DECRYPT_OK = 0,
        TLS_DECRYPT_INTERNAL = -1,
        TLS_DECRYPT_BAD_MAC = -2,
    };

    /* Values for the tls_offload field in CQE. */
    enum tls_rx_decrypted {
        TLS_RX_ENCRYPTED = 0x0,
        TLS_RX_DECRYPTED = 0x1,
        TLS_RX_RESYNC = 0x2,
        TLS_RX_AUTH_FAIL = 0x3,
    };

    enum tls_record_tracker_state {
        TLS_TRACKER_START = 0x0,
        TLS_TRACKER_TRACKING = 0x1,
        TLS_TRACKER_SEARCHING = 0x2,
    };

    enum tls_auth_state {
        TLS_AUTH_NO_OFFLOAD = 0x0,
        TLS_AUTH_OFFLOAD = 0x1,
        TLS_AUTH_AUTHENTICATION = 0x2,
    };

    ring *m_p_tx_ring;
    ring *m_p_rx_ring;

    /* Crypto info provided by application. */
    struct xlio_tls_info m_tls_info_tx;
    struct xlio_tls_info m_tls_info_rx;

    /* Whether offload is configured. */
    bool m_is_tls_tx;
    bool m_is_tls_rx;
    /* TLS record overhead (header + trailer). Different across versions. */
    uint32_t m_tls_rec_overhead;

    /* TX specific fields */
    xlio_tis *m_p_tis;

    /* A buffer to keep multiple headers for zerocopy TLS records. */
    mem_buf_desc_t *m_zc_stor;
    /* Offset of the next free chunk in the buffer to be allocated for a zerocopy record. */
    uint32_t m_zc_stor_offset;
    /* TX flow expects in-order TCP segments. */
    uint32_t m_expected_seqno;
    /* Track TX record number for TX resync flow. */
    uint64_t m_next_recno_tx;

    /* RX specific fields */
    xlio_tir *m_p_tir;

    /* OpenSSL objects for SW decryption. */
    void *m_p_evp_cipher;
    void *m_p_cipher_ctx;

    /* List of RX buffers that contain unhandled records. */
    xlio_desc_list_t m_rx_bufs;
    /* Record number of current or incomplete TLS record. */
    uint64_t m_next_recno_rx;
    /* Offset of the first unhandled record. */
    uint32_t m_rx_offset;
    /* Size of the first unhandled record. */
    uint32_t m_rx_rec_len;
    /* Number of bytes received after m_rx_offset. */
    uint32_t m_rx_rec_rcvd;
    /* State machine for TLS RX stream. */
    enum tls_rx_state m_rx_sm;
    /* Refused data by sockinfo_tcp::rx_lwip_cb() to be retried. */
    struct pbuf *m_refused_data;
    /* TLS flow steering rule. Created from an existing TCP rfs object. */
    rfs_rule *m_rx_rule;
    /* Buffer to hold GET_PSV data during resync. */
    mem_buf_desc_t *m_rx_psv_buf;
    /* Record number where resync request was received. */
    uint64_t m_rx_resync_recno;
};

#endif /* DEFINED_UTLS */
#endif /* _SOCKINFO_ULP_H */
