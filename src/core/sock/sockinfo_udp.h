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

#ifndef SOCKINFO_H
#define SOCKINFO_H

#include <list>
#include <vector>
#include <netinet/in.h>

#include "config.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"

#include "xlio_extra.h"
#include "util/chunk_list.h"
#include "util/xlio_stats.h"
#include "util/sys_vars.h"
#include "proto/mem_buf_desc.h"
#include "proto/dst_entry_udp.h"

#include "sock-redirect.h"
#include "sockinfo.h"

// Send flow dst_entry map
typedef std::unordered_map<sock_addr, dst_entry *> dst_entry_map_t;

typedef union {
    struct ip_mreq mreq;
    struct ip_mreq_source mreq_src;
    struct ip_mreqn mreqn;
    struct ipv6_mreq ip6_mreq;
    struct group_req greq;
    struct group_source_req gsreq;
} mc_req_all;

struct mc_pending_pram {
    ip_address mc_grp;
    ip_address mc_if;
    ip_address mc_src;
    mc_req_all req;
    int optname;
    int if_index;
    int pram_size;
    bool is_ipv6;
};

// Multicast pending list
typedef std::list<struct mc_pending_pram> mc_pram_list_t;
typedef std::unordered_map<ip_address, std::unordered_map<ip_address, int>> mc_memberships_map_t;

/**
 * @class udp sockinfo
 * Represents an udp socket.
 */
class sockinfo_udp : public sockinfo {
public:
    sockinfo_udp(int fd, int domain);
    ~sockinfo_udp() override;

    void setPassthrough() override
    {
        IF_STATS(m_p_socket_stats->b_is_offloaded = m_sock_offload = false);
    }
    bool isPassthrough() override { return !m_sock_offload; }

    int prepare_to_connect(const sockaddr *__to, socklen_t __tolen);

    int bind_no_os();
    int bind(const struct sockaddr *__addr, socklen_t __addrlen) override;
    int connect(const struct sockaddr *__to, socklen_t __tolen) override;
    void clean_socket_obj() override { delete this; }
    bool is_writeable() override { return true; };
    bool is_errorable(int *errors) override
    {
        NOT_IN_USE(errors);
        return false;
    }
    bool is_outgoing() override { return false; }
    bool is_incoming() override { return false; }
    int shutdown(int __how) override;
    int prepareListen() override { return 0; }
    int listen(int backlog) override;
    int accept(struct sockaddr *__addr, socklen_t *__addrlen) override;
    int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags) override;
    int getsockname(sockaddr *__name, socklen_t *__namelen) override;
    int getpeername(sockaddr *__name, socklen_t *__namelen) override;
    int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen) override;
    int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen) override;

    int resolve_if_ip(const int if_index, const ip_address &ip, ip_address &resolved_ip);
    int fill_mc_structs_ip6(int optname, const void *optval, mc_pending_pram *mcpram);
    int multicast_membership_setsockopt_ip6(int optname, const void *optval, socklen_t optlen);
    inline int fill_mreq_with_ix(void *mreq, int if_index, bool is_ipv6);

    /**
     * Sampling the OS immediately by matching the m_rx_udp_poll_os_ratio_counter
     * to the limit (safe_mce_sys().rx_udp_poll_os_ratio)
     */
    void set_immediate_os_sample() override;
    /**
     * Reseting m_rx_udp_poll_os_ratio_counter counter to prevent sampling OS immediately
     */
    void unset_immediate_os_sample() override;
    /**
     * Process a Rx request, we might have a ready packet, or we might block until
     * we have one (if sockinfo::m_b_blocking == true)
     */
    ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags,
               sockaddr *__from = nullptr, socklen_t *__fromlen = nullptr,
               struct msghdr *__msg = nullptr) override;
    /**
     * Check that a call to this sockinfo rx() will not block
     * -> meaning, we got an offloaded ready rx datagram
     * Return 'true' if would not block, 'false' if might block.
     *
     * While polling CQ, the fd_array is filled with a list of newly queued packets FD's
     */
    bool is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = nullptr) override;
    /**
     * Arm the event channel(s) assosiated with this sockinfo
     * Fill the fd_set (p_rxfds) with the correct fd channel values and the p_nfds with the (max_fd
     * + 1) Fill the p_cq_mgr_fd_map with the pointer to the cq_mgr_rx asosiated with the fd Return
     * count of channels (fds) that where mapped
     */
    int rx_request_notification(uint64_t poll_sn);
    /**
     * Process a Tx request, handle all that is needed to send the packet, we might block
     * until the connection info is ready or a tx buffer is releast (if sockinfo::m_b_blocking ==
     * true)
     */
    ssize_t tx(xlio_tx_call_attr_t &tx_arg) override;
    /**
     * Check that a call to this sockinof rx() will not block
     * -> meaning, we got a ready rx packet
     */
    void rx_add_ring_cb(ring *p_ring) override;
    void rx_del_ring_cb(ring *p_ring) override;
    int rx_verify_available_data() override;

    /**
     *	This callback will handle ready rx packet notification,
     *	in case packet is OK, completion for SOCKETXTREME mode
     *	will be filled or in other cases packet go to ready queue.
     *	If packet to be discarded, packet ref. counter will not be
     *	incremented and method returns false.
     *	Normally it is single point from sockinfo to be called from ring level.
     */
    bool rx_input_cb(mem_buf_desc_t *p_desc, void *pv_fd_ready_array) override;

    // This call will handle all rdma related events (bind->listen->connect_req->accept)
    void statistics_print(vlog_levels_t log_level = VLOG_DEBUG) override;
    int recvfrom_zcopy_free_packets(struct xlio_recvfrom_zcopy_packet_t *pkts,
                                    size_t count) override;
    inline fd_type_t get_type() override { return FD_TYPE_SOCKET; }

    bool prepare_to_close(bool process_shutdown = false) override;
    void update_header_field(data_updater *updater) override;

#if defined(DEFINED_NGINX)
    void prepare_to_close_socket_pool(bool _push_pop) override;
    void set_params_for_socket_pool() override
    {
        m_is_for_socket_pool = true;
        set_rx_num_buffs_reuse(safe_mce_sys().nginx_udp_socket_pool_rx_num_buffs_reuse);
    }
    bool is_closable() override { return !m_is_for_socket_pool; }
#else
    bool is_closable() override { return true; }
#endif

    int register_callback(xlio_recv_callback_t callback, void *context) override
    {
        return register_callback_ctx(callback, context);
    }

protected:
    void lock_rx_q() override { m_lock_rcv.lock(); }
    void unlock_rx_q() override { m_lock_rcv.unlock(); }

private:
    bool packet_is_loopback(mem_buf_desc_t *p_desc);
    ssize_t check_payload_size(const iovec *p_iov, ssize_t sz_iov);
    int mc_change_membership_start_helper_ip4(const ip_address &mc_grp, int optname);
    int mc_change_membership_end_helper_ip4(const ip_address &mc_grp, int optname,
                                            const ip_address &mc_src);
    int mc_change_membership_ip4(const mc_pending_pram *p_mc_pram);

    int mc_change_membership_ip6(const mc_pending_pram *p_mc_pram);
    int mc_change_membership_start_helper_ip6(const mc_pending_pram *p_mc_pram);
    int mc_change_membership_end_helper_ip6(const mc_pending_pram *p_mc_pram);
    int mc_change_pending_mreq(const mc_pending_pram *p_mc_pram);
    int on_sockname_change(struct sockaddr *__name, socklen_t __namelen);
    void handle_pending_mreq();
    void original_os_setsockopt_helper(const void *pram, int pram_size, int optname, int level);
    /* helper functions */
    void set_blocking(bool is_blocked) override;

    void rx_ready_byte_count_limit_update(
        size_t n_rx_ready_bytes_limit); // Drop rx ready packets from head of queue
    void drop_rx_ready_byte_count(size_t n_rx_bytes_limit);

    void
    save_stats_threadid_rx(); // ThreadId will only saved if logger is at least in DEBUG(4) level
    void
    save_stats_threadid_tx(); // ThreadId will only saved if logger is at least in DEBUG(4) level

    void save_stats_tx_offload(int bytes, bool is_dummy);

    inline int rx_wait(bool blocking);
    inline int poll_os();

    virtual inline void reuse_buffer(mem_buf_desc_t *buff);
    mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc) override;
    mem_buf_desc_t *get_next_desc_peek(mem_buf_desc_t *p_desc, int &rx_pkt_ready_list_idx) override;
    timestamps_t *get_socket_timestamps() override;
    void update_socket_timestamps(timestamps_t *) override {};

    inline void return_reuse_buffers_postponed()
    {
        if (!m_rx_reuse_buf_postponed) {
            return;
        }

        // for the parallel reclaim mechanism from internal thread, used for "silent" sockets
        set_rx_reuse_pending(false);

        m_rx_reuse_buf_postponed = false;

        rx_ring_map_t::iterator iter = m_rx_ring_map.begin();
        while (iter != m_rx_ring_map.end()) {
            descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
            int &n_buff_num = iter->second->rx_reuse_info.n_buff_num;
            if (n_buff_num >= m_rx_num_buffs_reuse) {
                if (iter->first->reclaim_recv_buffers(rx_reuse)) {
                    n_buff_num = 0;
                } else {
                    m_rx_reuse_buf_postponed = true;
                }
            }
            ++iter;
        }
    }

    inline xlio_recv_callback_retval_t inspect_by_user_cb(mem_buf_desc_t *p_desc);
    inline void rx_udp_cb_socketxtreme_helper(mem_buf_desc_t *p_desc);
    inline void update_ready(mem_buf_desc_t *p_rx_wc_buf_desc, void *pv_fd_ready_array,
                             xlio_recv_callback_retval_t cb_ret);

    void post_deqeue(bool release_buff) override;
    int zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) override;
    size_t handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                            int *p_out_flags) override;
    void handle_ip_pktinfo(struct cmsg_state *cm_state) override;

    mem_buf_desc_t *get_front_m_rx_pkt_ready_list() override;
    size_t get_size_m_rx_pkt_ready_list() override;
    void pop_front_m_rx_pkt_ready_list() override;
    void push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff) override;

private:
    struct port_socket_t {

        int port;
        int fd;

        bool operator==(const int &r_port) { return port == r_port; }
    };

    uint32_t m_rx_ready_byte_limit;
    ip_addr m_mc_tx_src_ip;
    bool m_b_mc_tx_loop;
    uint8_t m_n_mc_ttl_hop_lim;

    int32_t m_loops_to_go; // local param for polling loop on this socket
    uint32_t
        m_rx_udp_poll_os_ratio_counter; // Data member which sets how many offloaded polls on the cq
                                        // we want to do before doing an OS poll, on this socket
    bool m_sock_offload;

    mc_pram_list_t m_pending_mreqs;
    mc_memberships_map_t m_mc_memberships_map;
    uint32_t m_mc_num_grp_with_src_filter;

    lock_spin m_port_map_lock;
    std::vector<struct port_socket_t> m_port_map;
    unsigned m_port_map_index;

    dst_entry_map_t m_dst_entry_map;
    dst_entry *m_p_last_dst_entry;
    sock_addr m_last_sock_addr;

    chunk_list_t<mem_buf_desc_t *> m_rx_pkt_ready_list;

    uint8_t m_tos;

    const uint32_t m_n_sysvar_rx_poll_yield_loops;
    const uint32_t m_n_sysvar_rx_udp_poll_os_ratio;
    const uint32_t m_n_sysvar_rx_ready_byte_min_limit;
    const uint32_t m_n_sysvar_rx_cq_drain_rate_nsec;
    const uint32_t m_n_sysvar_rx_delta_tsc_between_cq_polls;

    bool m_sockopt_mapped; // setsockopt IPPROTO_UDP UDP_MAP_ADD
    bool m_is_connected; // to inspect for in_addr.src
    bool m_multicast; // true when socket set MC rule
};
#endif
