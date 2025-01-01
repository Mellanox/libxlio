/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

#ifndef MEM_BUF_DESC_H
#define MEM_BUF_DESC_H

#include <linux/errqueue.h>
#include <cstddef>

#include "utils/atomic.h"
#include "core/util/sock_addr.h"
#include "core/util/xlio_list.h"
#include "core/lwip/pbuf.h"

// Forward declarations
class ring_slave;
struct iphdr;
struct ip6_hdr;
struct xlio_buf;

struct timestamps_t {
    struct timespec sw;
    union {
        struct timespec hw;
        uint64_t hw_raw;
    };
};

/**
 * mem_buf_desc_t struct is used as the mapping of the wr_id in the wce to:
 * (1) p_desc_owner - to notify the owner of this mem_buf_desc of a completion of this WR
 *        Transmitting object (sockinfo) - reference counting for TX limit logic on TX completion
 *        Receiving object (ib_conn_mgr) - processing of the incoming ip packet on RX completion
 * (2) p_next_desc is used to link a few mem_buf_desc_t object on a list (free list,
 * 	TX fragment list, TX waiting completion signal list)
 * (3) p_buffer is the data buffer pointer (to be reused for TX or the ready
 * 	received data in TX)
 */
class mem_buf_desc_t {
public:
    enum flags { TYPICAL = 0, CLONED = 0x01, ZCOPY = 0x02 };

public:
    mem_buf_desc_t(uint8_t *buffer, size_t size, pbuf_type type)
        : p_buffer(buffer)
        , m_flags(mem_buf_desc_t::TYPICAL)
        , lkey(0)
        , p_next_desc(nullptr)
        , p_prev_desc(nullptr)
        , sz_buffer(size)
        , sz_data(0)
        , p_desc_owner(nullptr)
        , unused_padding {0}
    {
        memset(&lwip_pbuf, 0, sizeof(lwip_pbuf));
        clear_transport_data();
        memset(&ee, 0, sizeof(ee));
        reset_ref_count();

        lwip_pbuf.type = type;
    }

    // Copy constructor for the clone() method.
    mem_buf_desc_t(const mem_buf_desc_t &ref)
    {
        // mem_buf_desc_t contains only list_node and sock_addr as class fields.
        memcpy((void *)this, &ref, sizeof(mem_buf_desc_t));
    }

    inline mem_buf_desc_t *clone()
    {
        mem_buf_desc_t *p_desc = new mem_buf_desc_t(*this);
        INIT_LIST_HEAD(&p_desc->buffer_node.head);
        p_desc->m_flags |= mem_buf_desc_t::CLONED;
        return p_desc;
    }

    // Destructor specifically for cloned buffers.
    ~mem_buf_desc_t() {}

    inline void clear_transport_data(void)
    {
        // rx field is the largest in the union, this clears tx as well.
        memset((void *)&rx, 0, sizeof(rx));
    }

    inline int get_ref_count() const { return atomic_read(&n_ref_count); }
    inline void reset_ref_count() { atomic_set(&n_ref_count, 0); }
    inline void set_ref_count(int x) { atomic_set(&n_ref_count, x); }
    inline int inc_ref_count() { return atomic_fetch_and_inc(&n_ref_count); }
    inline int dec_ref_count() { return atomic_fetch_and_dec(&n_ref_count); }
    inline int add_ref_count(int x) { return atomic_fetch_add_relaxed(x, &n_ref_count); }
    inline unsigned int lwip_pbuf_get_ref_count() const { return lwip_pbuf.ref; }
    inline unsigned int lwip_pbuf_inc_ref_count() { return ++lwip_pbuf.ref; }
    inline unsigned int lwip_pbuf_dec_ref_count()
    {
        if (likely(lwip_pbuf.ref)) {
            --lwip_pbuf.ref;
        }
        return lwip_pbuf.ref;
    }

    /*
     * Reuse field 'ee' as 'userdata' within xlio_buf. This can be any field of sufficient size
     * which is unused in RX buffers.
     * This is used for XLIO Socket API.
     */
    struct xlio_buf *to_xlio_buf() { return reinterpret_cast<struct xlio_buf *>(&ee); }
    static struct xlio_buf *to_xlio_buf(struct pbuf *p)
    {
        return reinterpret_cast<mem_buf_desc_t *>(p)->to_xlio_buf();
    }
    static mem_buf_desc_t *from_xlio_buf(struct xlio_buf *buf)
    {
        return reinterpret_cast<mem_buf_desc_t *>(reinterpret_cast<char *>(buf) -
                                                  offsetof(mem_buf_desc_t, ee));
    }

public:
    /* This field must be first in this class. It encapsulates pbuf structure from lwip */
    struct pbuf lwip_pbuf;
    uint8_t *p_buffer;

    static inline size_t buffer_node_offset(void)
    {
        return NODE_OFFSET(mem_buf_desc_t, buffer_node);
    }
    list_node<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> buffer_node;

    union {
        struct {
            iovec frag; // Datagram part base address and length
            sock_addr src;
            sock_addr dst;

            size_t sz_payload; // This is the total amount of data of the packet, if
                               // (sz_payload>sz_data) means fragmented packet.
            timestamps_t timestamps;
            void *context;

            union {
                struct {
                    union {
                        struct iphdr *p_ip4_h;
                        struct ip6_hdr *p_ip6_h;
                        void *p_ip_h;
                    };
                    struct tcphdr *p_tcp_h;
                } tcp;
                struct {
                    int ifindex; // Incoming interface index
                } udp;
            };

            size_t n_transport_header_len;
            uint32_t flow_tag_id; // Flow Tag ID of this received packet
            int8_t n_frags; // number of fragments
            bool is_xlio_thr; // specify whether packet drained from XLIO internal thread or from
                              // user app thread
            bool is_sw_csum_need; // specify if software checksum is need for this packet
#ifdef DEFINED_UTLS
            uint8_t tls_decrypted;
            uint8_t tls_type;
#endif /* DEFINED_UTLS */
            uint16_t strides_num;
        } rx;
        struct {
            size_t dev_mem_length; // Total data aligned to 4 bytes.
            union {
                struct iphdr *p_ip4_h;
                struct ip6_hdr *p_ip6_h;
                void *p_ip_h;
            };
            union {
                struct udphdr *p_udp_h;
                struct tcphdr *p_tcp_h;
            };
            struct {
                /* This structure allows to track tx zerocopy flow
                 * including start send id and range in count field
                 * with total bytes length as len
                 * where
                 * id -> ee.ee_info
                 * id + count -1 -> ee.ee_data
                 */
                uint32_t id;
                uint32_t len;
                uint16_t count;
                void *ctx;
                void (*callback)(mem_buf_desc_t *);
            } zc;
        } tx;
    };

    /* This field is needed for error queue processing */
    struct sock_extended_err ee;
    int m_flags; /* object description */
    uint32_t lkey; // Buffers lkey for QP access
    mem_buf_desc_t *p_next_desc; // A general purpose linked list of mem_buf_desc
    mem_buf_desc_t *p_prev_desc;
    size_t sz_buffer; // this is the size of the buffer
    size_t sz_data; // this is the amount of data inside the buffer (sz_data <= sz_buffer)

    // Tx: cq_mgr_tx owns the mem_buf_desc and the associated data buffer
    // Rx: cq_mgr_rx owns the mem_buf_desc and the associated data buffer
    ring_slave *p_desc_owner;

    atomic_t n_ref_count; // number of interested receivers (sockinfo) [can be modified only in
                          // cq_mgr_rx context]
    uint64_t unused_padding[2]; // Align the structure to the cache line boundary
};

typedef xlio_list_t<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> descq_t;

#endif
