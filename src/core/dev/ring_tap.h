/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
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

#ifndef RING_TAP_H_
#define RING_TAP_H_

#include "ring_slave.h"
#include "util/agent.h"

class ring_tap : public ring_slave {
public:
    ring_tap(int if_index, ring *parent);
    virtual ~ring_tap();

    virtual bool is_up() { return (m_vf_ring || m_active); }
    virtual bool attach_flow(flow_tuple &flow_spec_5t, sockinfo *sink, bool force_5t = false);
    virtual bool detach_flow(flow_tuple &flow_spec_5t, sockinfo *sink);
    virtual bool poll_and_process_element_rx(void *pv_fd_ready_array = NULL);
    virtual int poll_and_process_element_tx() { return 0; }
    virtual void clear_rx_notification() {};
    virtual int drain_and_proccess();
    virtual bool reclaim_recv_buffers(descq_t *rx_reuse);
    virtual bool reclaim_recv_buffers(mem_buf_desc_t *buff);
    virtual void send_ring_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                  xlio_wr_tx_packet_attr attr);
    virtual int send_lwip_buffer(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe,
                                 xlio_wr_tx_packet_attr attr, xlio_tis *tis);
    virtual void mem_buf_desc_return_single_to_owner_tx(mem_buf_desc_t *p_mem_buf_desc);
    virtual void mem_buf_desc_return_single_multi_ref(mem_buf_desc_t *p_mem_buf_desc, unsigned ref);
    virtual mem_buf_desc_t *mem_buf_tx_get(ring_user_id_t id, bool b_block, pbuf_type type,
                                           int n_num_mem_bufs = 1);
    virtual int mem_buf_tx_release(mem_buf_desc_t *p_mem_buf_desc_list, bool b_accounting,
                                   bool trylock = false);
    virtual bool get_hw_dummy_send_support(ring_user_id_t id, xlio_ibv_send_wr *p_send_wqe)
    {
        NOT_IN_USE(id);
        NOT_IN_USE(p_send_wqe);
        return false;
    }
    virtual bool request_notification(cq_type_t cq_type)
    {
        NOT_IN_USE(cq_type);
        return 0;
    }
    virtual void adapt_cq_moderation() {}

    virtual int modify_ratelimit(struct xlio_rate_limit_t &rate_limit)
    {
        NOT_IN_USE(rate_limit);
        return 0;
    }
    void inc_cq_moderation_stats() {}
    virtual uint32_t get_tx_user_lkey(void *addr, size_t length)
    {
        NOT_IN_USE(addr);
        NOT_IN_USE(length);
        return LKEY_ERROR;
    }
    virtual uint32_t get_max_inline_data() { return 0; }
    ib_ctx_handler *get_ctx(ring_user_id_t id)
    {
        NOT_IN_USE(id);
        return nullptr;
    }
    virtual uint32_t get_max_send_sge(void) { return 1; }
    virtual uint32_t get_max_payload_sz(void) { return 0; }
    virtual uint16_t get_max_header_sz(void) { return 0; }
    virtual uint32_t get_tx_lkey(ring_user_id_t id)
    {
        NOT_IN_USE(id);
        return 0;
    }
    virtual bool is_tso(void) { return false; }

    inline void set_tap_data_available() { m_tap_data_available = true; }
    inline void set_vf_ring(ring_slave *p_ring) { m_vf_ring = p_ring; }
    inline void inc_vf_plugouts() { m_p_ring_stat->tap.n_vf_plugouts++; }
    uint32_t send_doca_single(void *ptr, uint32_t len, mem_buf_desc_t *buff)
    {
        NOT_IN_USE(ptr);
        NOT_IN_USE(len);
        NOT_IN_USE(buff);
        return -1;
    }
    uint32_t send_doca_lso(struct iovec &h, struct pbuf *p, bool is_zerocopy)
    {
        NOT_IN_USE(h);
        NOT_IN_USE(p);
        NOT_IN_USE(is_zerocopy);
        return -1;
    }

private:
    inline void return_to_global_pool();
    int prepare_flow_message(xlio_msg_flow &data, msg_flow_t flow_action, flow_tuple &flow_spec_5t);
    int prepare_flow_message(xlio_msg_flow &data, msg_flow_t flow_action);
    int process_element_rx(void *pv_fd_ready_array);
    bool request_more_rx_buffers();
    int send_buffer(xlio_ibv_send_wr *p_send_wqe, xlio_wr_tx_packet_attr attr);
    void send_status_handler(int ret, xlio_ibv_send_wr *p_send_wqe);
    void tap_create(net_device_val *p_ndev);
    void tap_destroy();

    /* These fields are NETVSC mode specific */
    int m_tap_fd; /* file descriptor of tap device */
    ring_slave *m_vf_ring;
    const uint32_t m_sysvar_qp_compensation_level;
    descq_t m_rx_pool;
    bool m_tap_data_available;
};

#endif /* RING_TAP_H_ */
