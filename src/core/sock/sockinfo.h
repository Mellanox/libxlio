/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <unordered_map>
#include <ifaddrs.h>

#include "config.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "xlio_extra.h"
#include "util/data_updater.h"
#include "util/sock_addr.h"
#include "util/xlio_stats.h"
#include "util/sys_vars.h"
#include "util/wakeup_pipe.h"
#include "proto/flow_tuple.h"
#include "proto/mem_buf_desc.h"
#include "proto/dst_entry.h"
#include "dev/net_device_table_mgr.h"
#include "dev/ring_simple.h"
#include "dev/ring_allocation_logic.h"

#include "socket_fd_api.h"
#include "pkt_rcvr_sink.h"
#include "pkt_sndr_source.h"
#include "sock-redirect.h"

#ifndef BASE_SOCKINFO_H
#define BASE_SOCKINFO_H

#define SI_RX_EPFD_EVENT_MAX   16
#define BYTE_TO_KB(byte_value) ((byte_value) / 125)
#define KB_TO_BYTE(kbit_value) ((kbit_value)*125)

#if DEFINED_MISSING_NET_TSTAMP
enum {
    SOF_TIMESTAMPING_TX_HARDWARE = (1 << 0),
    SOF_TIMESTAMPING_TX_SOFTWARE = (1 << 1),
    SOF_TIMESTAMPING_RX_HARDWARE = (1 << 2),
    SOF_TIMESTAMPING_RX_SOFTWARE = (1 << 3),
    SOF_TIMESTAMPING_SOFTWARE = (1 << 4),
    SOF_TIMESTAMPING_SYS_HARDWARE = (1 << 5),
    SOF_TIMESTAMPING_RAW_HARDWARE = (1 << 6),
    SOF_TIMESTAMPING_MASK = (SOF_TIMESTAMPING_RAW_HARDWARE - 1) | SOF_TIMESTAMPING_RAW_HARDWARE
};
#else
#include <linux/net_tstamp.h>
#endif

#ifndef SO_TIMESTAMPNS
#define SO_TIMESTAMPNS 35
#endif

#ifndef SO_TIMESTAMPING
#define SO_TIMESTAMPING 37
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef SO_EE_ORIGIN_ZEROCOPY
#define SO_EE_ORIGIN_ZEROCOPY 5
#endif

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 59
#endif

#ifndef SO_EE_CODE_ZEROCOPY_COPIED
#define SO_EE_CODE_ZEROCOPY_COPIED 1
#endif

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif

struct cmsg_state {
    struct msghdr *mhdr;
    struct cmsghdr *cmhdr;
    size_t cmsg_bytes_consumed;
};

#define NOTIFY_ON_EVENTS(context, events) context->set_events(events)

struct buff_info_t {
    buff_info_t()
    {
        rx_reuse.set_id("buff_info_t (%p) : rx_reuse", this);
        n_buff_num = 0;
    }

    int n_buff_num;
    descq_t rx_reuse;
};

typedef struct {
    net_device_entry *p_nde;
    net_device_val *p_ndv;
    ring *p_ring;
    int refcnt;
} net_device_resources_t;

typedef std::unordered_map<ip_addr, net_device_resources_t> rx_net_device_map_t;

/*
 * Sockinfo setsockopt() return values
 */
#define SOCKOPT_INTERNAL_XLIO_SUPPORT 0 // Internal socket option, should not pass request to OS.
#define SOCKOPT_NO_XLIO_SUPPORT                                                                    \
    -1 // Socket option was found but not supported, error should be returned to user.
#define SOCKOPT_PASS_TO_OS   1 // Should pass to TCP/UDP level or OS.
#define SOCKOPT_HANDLE_BY_OS -2 // Pass the option also to the OS.

typedef std::unordered_map<flow_tuple_with_local_if, ring *> rx_flow_map_t;

typedef struct {
    int refcnt;
    buff_info_t rx_reuse_info;
} ring_info_t;

typedef std::unordered_map<ring *, ring_info_t *> rx_ring_map_t;

// see route.c in Linux kernel
const uint8_t ip_tos2prio[16] = {0, 0, 0, 0, 2, 2, 2, 2, 6, 6, 6, 6, 4, 4, 4, 4};

class sockinfo : public socket_fd_api,
                 public pkt_rcvr_sink,
                 public pkt_sndr_source,
                 public wakeup_pipe {
public:
    sockinfo(int fd, int domain, bool use_ring_locks);
    virtual ~sockinfo();

    enum sockinfo_state {
        SOCKINFO_UNDEFINED,
        SOCKINFO_OPENED,
        SOCKINFO_CLOSING,
        SOCKINFO_CLOSED,
        SOCKINFO_DESTROYING
    };

#ifdef DEFINED_NGINX
    virtual void copy_sockopt_fork(const socket_fd_api *copy_from);
    void set_m_n_sysvar_rx_num_buffs_reuse(int val) { m_n_sysvar_rx_num_buffs_reuse = val; }
#endif

    virtual void consider_rings_migration();
    virtual int add_epoll_context(epfd_info *epfd);
    virtual void remove_epoll_context(epfd_info *epfd);

    inline bool set_flow_tag(uint32_t flow_tag_id)
    {
        if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
            m_flow_tag_id = flow_tag_id;
            m_flow_tag_enabled = true;
            return true;
        }
        m_flow_tag_id = FLOW_TAG_MASK;
        return false;
    }
    inline bool flow_tag_enabled(void) { return m_flow_tag_enabled; }
    inline int get_rx_epfd(void) { return m_rx_epfd; }
    inline bool is_blocking(void) { return m_b_blocking; }

    virtual bool flow_in_reuse(void) { return false; };
    virtual int *get_rings_fds(int &res_length);
    virtual int get_rings_num();
    virtual bool check_rings() { return m_p_rx_ring ? true : false; }
    virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG);
    uint32_t get_flow_tag_val() { return m_flow_tag_id; }
    inline in_protocol_t get_protocol(void) { return m_protocol; }

    bool validate_and_convert_mapped_ipv4(sock_addr &sock) const;
    void socket_stats_init(void);

    socket_stats_t *m_p_socket_stats;

    void sock_pop_descs_rx_ready(descq_t *cache)
    {
        lock_rx_q();
        mem_buf_desc_t *temp;
        const size_t size = get_size_m_rx_pkt_ready_list();

        for (size_t i = 0; i < size; i++) {
            temp = get_front_m_rx_pkt_ready_list();
            pop_front_m_rx_pkt_ready_list();
            cache->push_back(temp);
        }
        m_n_rx_pkt_ready_list_count = 0;
        m_rx_ready_byte_count = 0;
        m_p_socket_stats->n_rx_ready_pkt_count = 0;
        m_p_socket_stats->n_rx_ready_byte_count = 0;

        unlock_rx_q();
    }

    sa_family_t get_family() { return m_family; }
    /* Last memory descriptor with zcopy operation method */
    mem_buf_desc_t *m_last_zcdesc;
    struct {
        /* Track internal events to return in socketxtreme_poll()
         * Current design support single event for socket at a particular time
         */
        struct ring_ec ec_cache;
        struct ring_ec *ec;
    } m_socketxtreme;

    rfs *rfs_ptr = nullptr;

private:
    int fcntl_helper(int __cmd, unsigned long int __arg, bool &bexit);
    bool attach_as_uc_receiver_anyip(sa_family_t family, role_t role, bool skip_rules);

protected:
    bool m_flow_tag_enabled; // for this socket
    bool m_b_blocking;
    bool m_b_pktinfo;
    bool m_b_rcvtstamp;
    bool m_b_rcvtstampns;
    bool m_b_zc;
    bool m_skip_cq_poll_in_rx;
    uint8_t m_n_tsing_flags;
    in_protocol_t m_protocol;
    uint8_t m_src_sel_flags;

    multilock m_lock_rcv;
    lock_mutex m_lock_snd;
    lock_mutex m_rx_migration_lock;

    sockinfo_state m_state; // socket current state
    sa_family_t m_family;
    sock_addr m_bound;
    sock_addr m_connected;
    dst_entry *m_p_connected_dst_entry;
    ip_addr m_so_bindtodevice_ip;

    socket_stats_t m_socket_stats;

    int m_rx_epfd;
    cache_observer m_rx_nd_observer;
    rx_net_device_map_t m_rx_nd_map;
    rx_flow_map_t m_rx_flow_map;
    // we either listen on ALL system cqs or bound to the specific cq
    ring *m_p_rx_ring; // used in TCP/UDP
    buff_info_t m_rx_reuse_buff; // used in TCP instead of m_rx_ring_map
    bool m_rx_reuse_buf_pending; // used to periodically return buffers, even if threshold was not
                                 // reached
    bool m_rx_reuse_buf_postponed; // used to mark threshold was reached, but free was not done yet
    inline void set_rx_reuse_pending(bool is_pending = true)
    {
        m_rx_reuse_buf_pending = is_pending;
    }

    rx_ring_map_t m_rx_ring_map; // CQ map
    lock_mutex_recursive m_rx_ring_map_lock;
    ring_allocation_logic_rx m_ring_alloc_logic;

    loops_timer m_loops_timer;

    /**
     * list of pending ready packet on the Rx,
     * each element is a pointer to the ib_conn_mgr that holds this ready rx datagram
     */
    int m_n_rx_pkt_ready_list_count;
    size_t m_rx_pkt_ready_offset;
    size_t m_rx_ready_byte_count;

    int m_n_sysvar_rx_num_buffs_reuse;
    const int32_t m_n_sysvar_rx_poll_num;
    ring_alloc_logic_attr m_ring_alloc_log_rx;
    ring_alloc_logic_attr m_ring_alloc_log_tx;
    uint32_t m_pcp;

    /* Socket error queue that keeps local errors and internal data required
     * to provide notification ability.
     */
    descq_t m_error_queue;
    lock_spin m_error_queue_lock;

    /* TX zcopy counter
     * The notification itself for tx zcopy operation is a simple scalar value.
     * Each socket maintains an internal unsigned 32-bit counter.
     * Each send call with MSG_ZEROCOPY that successfully sends data increments
     * the counter. The counter is not incremented on failure or if called with
     * length zero.
     * The counter counts system call invocations, not bytes.
     * It wraps after UINT_MAX calls.
     */
    atomic_t m_zckey;

    // Callback function pointer to support VMA extra API (xlio_extra.h)
    xlio_recv_callback_t m_rx_callback;
    void *m_rx_callback_context; // user context
    struct xlio_rate_limit_t m_so_ratelimit;
    void *m_fd_context; // Context data stored with socket
    uint32_t m_flow_tag_id; // Flow Tag for this socket
    bool m_rx_cq_wait_ctrl;
    uint8_t m_n_uc_ttl_hop_lim;
    bool m_is_ipv6only;
    int *m_p_rings_fds;
    virtual void set_blocking(bool is_blocked);
    virtual int fcntl(int __cmd, unsigned long int __arg);
    virtual int fcntl64(int __cmd, unsigned long int __arg);
    virtual int ioctl(unsigned long int __request, unsigned long int __arg);
    virtual int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen);
    int setsockopt_kernel(int __level, int __optname, const void *__optval, socklen_t __optlen,
                          int supported, bool allow_priv);
    virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen);

    virtual mem_buf_desc_t *get_front_m_rx_pkt_ready_list() = 0;
    virtual size_t get_size_m_rx_pkt_ready_list() = 0;
    virtual void pop_front_m_rx_pkt_ready_list() = 0;
    virtual void push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff) = 0;

    void save_stats_rx_os(int bytes);
    void save_stats_tx_os(int bytes);
    void save_stats_rx_offload(int nbytes);

    virtual int rx_verify_available_data() = 0;
    virtual void update_header_field(data_updater *updater) = 0;
    virtual mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc) = 0;
    virtual mem_buf_desc_t *get_next_desc_peek(mem_buf_desc_t *p_desc,
                                               int &rx_pkt_ready_list_idx) = 0;
    virtual timestamps_t *get_socket_timestamps() = 0;
    virtual void update_socket_timestamps(timestamps_t *ts) = 0;
    virtual void post_deqeue(bool release_buff) = 0;
    virtual int os_epoll_wait(epoll_event *ep_events, int maxevents);
    virtual int zero_copy_rx(iovec *p_iov, mem_buf_desc_t *pdesc, int *p_flags) = 0;
    virtual int register_callback(xlio_recv_callback_t callback, void *context);

    virtual size_t handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                                    int *p_out_flags);

    bool attach_receiver(flow_tuple_with_local_if &flow_key);
    bool detach_receiver(flow_tuple_with_local_if &flow_key);
    net_device_resources_t *create_nd_resources(const ip_addr &ip_local);
    bool destroy_nd_resources(const ip_addr &ip_local);
    void do_rings_migration(resource_allocation_key &old_key);
    int set_ring_attr(xlio_ring_alloc_logic_attr *attr);
    int set_ring_attr_helper(ring_alloc_logic_attr *sock_attr, xlio_ring_alloc_logic_attr *attr);

    // Attach to all relevant rings for offloading receive flows - always used from slow path
    // According to bounded information we need to attach to all UC relevant flows
    // If local_ip is ANY then we need to attach to all offloaded interfaces OR to the one our
    // connected_ip is routed to
    bool attach_as_uc_receiver(role_t role, bool skip_rules = false);
    transport_t find_target_family(role_t role, const struct sockaddr *sock_addr_first,
                                   const struct sockaddr *sock_addr_second = NULL);

    // This callback will notify that socket is ready to receive and map the cq.
    virtual void rx_add_ring_cb(ring *p_ring);
    virtual void rx_del_ring_cb(ring *p_ring);

    virtual void lock_rx_q() { m_lock_rcv.lock(); }
    virtual void unlock_rx_q() { m_lock_rcv.unlock(); }

    void shutdown_rx();
    void destructor_helper();
    int modify_ratelimit(dst_entry *p_dst_entry, struct xlio_rate_limit_t &rate_limit);

    void move_descs(ring *p_ring, descq_t *toq, descq_t *fromq, bool own);
    void pop_descs_rx_ready(descq_t *cache, ring *p_ring = NULL);
    void push_descs_rx_ready(descq_t *cache);
    void reuse_descs(descq_t *reuseq, ring *p_ring = NULL);
    int set_sockopt_prio(__const void *__optval, socklen_t __optlen);
    bool ipv6_set_addr_sel_pref(int val);
    int ipv6_get_addr_sel_pref();

    virtual void handle_ip_pktinfo(struct cmsg_state *cm_state) = 0;
    inline void handle_recv_timestamping(struct cmsg_state *cm_state);
    inline void handle_recv_errqueue(struct cmsg_state *cm_state);
    void insert_cmsg(struct cmsg_state *cm_state, int level, int type, void *data, int len);
    void handle_cmsg(struct msghdr *msg, int flags);
    void process_timestamps(mem_buf_desc_t *p_desc);
    void add_cqfd_to_sock_rx_epfd(ring *p_ring);
    void remove_cqfd_from_sock_rx_epfd(ring *p_ring);
    int os_wait_sock_rx_epfd(epoll_event *ep_events, int maxevents);
    virtual bool try_un_offloading(); // un-offload the socket if possible
    virtual inline void do_wakeup()
    {
        if (!is_socketxtreme()) {
            wakeup_pipe::do_wakeup();
        }
    }

    bool is_shadow_socket_present() { return m_fd >= 0 && m_fd != m_rx_epfd; }
    inline bool is_socketxtreme() { return safe_mce_sys().enable_socketxtreme; }

    inline void set_events_socketxtreme(uint64_t events)
    {
        m_socketxtreme.ec->completion.user_data = (uint64_t)m_fd_context;
        if (!m_socketxtreme.ec->completion.events) {
            m_p_rx_ring->put_ec(m_socketxtreme.ec);
        }
        m_socketxtreme.ec->completion.events |= events;
    }

    inline void set_events(uint64_t events)
    {
        /* Collect all events if rx ring is enabled */
        if (is_socketxtreme() && m_state == SOCKINFO_OPENED) {
            set_events_socketxtreme(events);
        }

        socket_fd_api::notify_epoll_context((uint32_t)events);
    }

    inline void save_strq_stats(uint32_t packet_strides)
    {
        m_socket_stats.strq_counters.n_strq_total_strides += static_cast<uint64_t>(packet_strides);
        m_socket_stats.strq_counters.n_strq_max_strides_per_packet =
            std::max(m_socket_stats.strq_counters.n_strq_max_strides_per_packet, packet_strides);
    }

    inline int dequeue_packet(iovec *p_iov, ssize_t sz_iov, sockaddr *__from, socklen_t *__fromlen,
                              int in_flags, int *p_out_flags)
    {
        mem_buf_desc_t *pdesc;
        int total_rx = 0;
        uint32_t nbytes, pos;
        bool relase_buff = true;

        bool is_peek = in_flags & MSG_PEEK;
        int rx_pkt_ready_list_idx = 1;
        int rx_pkt_ready_offset = m_rx_pkt_ready_offset;

        pdesc = get_front_m_rx_pkt_ready_list();
        void *iov_base = (uint8_t *)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
        size_t bytes_left = pdesc->rx.frag.iov_len - m_rx_pkt_ready_offset;
        size_t payload_size = pdesc->rx.sz_payload;

        if (__from && __fromlen) {
            pdesc->rx.src.get_sa_by_family(__from, *__fromlen, m_family);
        }

        if (in_flags & MSG_XLIO_ZCOPY) {
            relase_buff = false;
            total_rx = zero_copy_rx(p_iov, pdesc, p_out_flags);
            if (unlikely(total_rx < 0)) {
                return -1;
            }
            m_rx_pkt_ready_offset = 0;
        } else {
#ifdef DEFINED_UTLS
            uint8_t tls_type = pdesc->rx.tls_type;
#endif /* DEFINED_UTLS */
            for (int i = 0; i < sz_iov && pdesc; i++) {
                pos = 0;
                while (pos < p_iov[i].iov_len && pdesc) {
#ifdef DEFINED_UTLS
                    if (unlikely(pdesc->rx.tls_type != tls_type)) {
                        break;
                    }
#endif /* DEFINED_UTLS */
                    nbytes = p_iov[i].iov_len - pos;
                    if (nbytes > bytes_left) {
                        nbytes = bytes_left;
                    }
                    memcpy((char *)(p_iov[i].iov_base) + pos, iov_base, nbytes);
                    pos += nbytes;
                    total_rx += nbytes;
                    m_rx_pkt_ready_offset += nbytes;
                    bytes_left -= nbytes;
                    iov_base = (uint8_t *)iov_base + nbytes;
                    if (m_b_rcvtstamp || m_n_tsing_flags) {
                        update_socket_timestamps(&pdesc->rx.timestamps);
                    }
                    if (bytes_left <= 0) {
                        if (unlikely(is_peek)) {
                            pdesc = get_next_desc_peek(pdesc, rx_pkt_ready_list_idx);
                        } else {
                            pdesc = get_next_desc(pdesc);
                        }
                        m_rx_pkt_ready_offset = 0;
                        if (pdesc) {
                            iov_base = pdesc->rx.frag.iov_base;
                            bytes_left = pdesc->rx.frag.iov_len;
                        }
                    }
                }
            }
        }

        if (unlikely(is_peek)) {
            m_rx_pkt_ready_offset =
                rx_pkt_ready_offset; // if MSG_PEEK is on, m_rx_pkt_ready_offset must be zero-ed
            // save_stats_rx_offload(total_rx); //TODO??
        } else {
            m_rx_ready_byte_count -= total_rx;
            m_p_socket_stats->n_rx_ready_byte_count -= total_rx;
            post_deqeue(relase_buff);
            save_stats_rx_offload(total_rx);
        }

        total_rx = handle_msg_trunc(total_rx, payload_size, in_flags, p_out_flags);

        return total_rx;
    }

    inline void reuse_buffer(mem_buf_desc_t *buff)
    {
        set_rx_reuse_pending(false);
        ring *p_ring = buff->p_desc_owner->get_parent();
        rx_ring_map_t::iterator iter = m_rx_ring_map.find(p_ring);
        if (likely(iter != m_rx_ring_map.end())) {
            if (safe_mce_sys().buffer_batching_mode == BUFFER_BATCHING_NONE) {
                if (!p_ring->reclaim_recv_buffers(buff)) {
                    g_buffer_pool_rx_ptr->put_buffer_after_deref_thread_safe(buff);
                }
                return;
            }

            descq_t *rx_reuse = &iter->second->rx_reuse_info.rx_reuse;
            int &n_buff_num = iter->second->rx_reuse_info.n_buff_num;
            rx_reuse->push_back(buff);
            n_buff_num += buff->rx.n_frags;
            if (n_buff_num < m_n_sysvar_rx_num_buffs_reuse) {
                return;
            }
            if (n_buff_num >= 2 * m_n_sysvar_rx_num_buffs_reuse) {
                if (p_ring->reclaim_recv_buffers(rx_reuse)) {
                    n_buff_num = 0;
                } else {
                    g_buffer_pool_rx_ptr->put_buffers_after_deref_thread_safe(rx_reuse);
                    n_buff_num = 0;
                }
                m_rx_reuse_buf_postponed = false;
            } else {
                m_rx_reuse_buf_postponed = true;
            }
        } else {
            // Retuned buffer to global pool when owner can't be found
            // In case ring was deleted while buffers where still queued
            vlog_printf(VLOG_DEBUG, "Buffer owner not found\n");
            // Awareness: these are best efforts: decRef without lock in case no CQ
            g_buffer_pool_rx_ptr->put_buffer_after_deref_thread_safe(buff);
        }
    }

    static const char *setsockopt_so_opt_to_str(int opt)
    {
        switch (opt) {
        case SO_REUSEADDR:
            return "SO_REUSEADDR";
        case SO_REUSEPORT:
            return "SO_REUSEPORT";
        case SO_BROADCAST:
            return "SO_BROADCAST";
        case SO_RCVBUF:
            return "SO_RCVBUF";
        case SO_SNDBUF:
            return "SO_SNDBUF";
        case SO_TIMESTAMP:
            return "SO_TIMESTAMP";
        case SO_TIMESTAMPNS:
            return "SO_TIMESTAMPNS";
        case SO_BINDTODEVICE:
            return "SO_BINDTODEVICE";
        case SO_ZEROCOPY:
            return "SO_ZEROCOPY";
        case SO_XLIO_RING_ALLOC_LOGIC:
            return "SO_XLIO_RING_ALLOC_LOGIC";
        case SO_MAX_PACING_RATE:
            return "SO_MAX_PACING_RATE";
        case SO_XLIO_FLOW_TAG:
            return "SO_XLIO_FLOW_TAG";
        case SO_XLIO_SHUTDOWN_RX:
            return "SO_XLIO_SHUTDOWN_RX";
        case IPV6_V6ONLY:
            return "IPV6_V6ONLY";
        case IPV6_ADDR_PREFERENCES:
            return "IPV6_ADDR_PREFERENCES";
        default:
            break;
        }
        return "UNKNOWN SO opt";
    }

    int get_sock_by_L3_L4(in_protocol_t protocol, const ip_address &ip, in_port_t port);

    //////////////////////////////////////////////////////////////////
    int handle_exception_flow()
    {
        if (safe_mce_sys().exception_handling.is_suit_un_offloading()) {
            try_un_offloading();
        }
        if (safe_mce_sys().exception_handling == xlio_exception_handling::MODE_RETURN_ERROR) {
            errno = EINVAL;
            return -1;
        }
        if (safe_mce_sys().exception_handling == xlio_exception_handling::MODE_ABORT) {
            return -2;
        }
        return 0;
    }
    //////////////////////////////////////////////////////////////////
};

#endif /* BASE_SOCKINFO_H */
