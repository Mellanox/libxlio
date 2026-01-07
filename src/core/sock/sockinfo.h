/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <unordered_map>
#include <deque>
#include <ifaddrs.h>
#include <sys/socket.h>
#include "config.h"
#include "xlio_extra.h"
#include "dev/cq_mgr_rx.h"
#include "dev/buffer_pool.h"
#include "sock/cleanable_obj.h"
#include "vlogger/vlogger.h"
#include "utils/lock_wrapper.h"
#include "util/data_updater.h"
#include "util/sock_addr.h"
#include "util/xlio_stats.h"
#include "util/sys_vars.h"
#include "util/wakeup_pipe.h"
#include "iomux/epfd_info.h"
#include "proto/flow_tuple.h"
#include "proto/mem_buf_desc.h"
#include "proto/dst_entry.h"
#include "dev/net_device_table_mgr.h"
#include "dev/ring_simple.h"
#include "dev/ring_allocation_logic.h"
#include "sock-redirect.h"
#include "sock-app.h"
#include "sock_stats.h"

#ifndef BASE_SOCKINFO_H
#define BASE_SOCKINFO_H

#define SI_RX_EPFD_EVENT_MAX   16
#define BYTE_TO_KB(byte_value) ((byte_value) / 125)
#define KB_TO_BYTE(kbit_value) ((kbit_value)*125)
#define FD_ARRAY_MAX           24

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 04000
#endif

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

#ifndef SO_MAX_PACING_RATE
#define SO_MAX_PACING_RATE 47
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

#define NOTIFY_ON_EVENTS(context, events) context->insert_epoll_event(events)

#define IF_STATS(x)                                                                                \
    if (unlikely(m_p_socket_stats)) {                                                              \
        (x);                                                                                       \
    }
#define IF_STATS_O(o, x)                                                                           \
    if (unlikely((o)->m_p_socket_stats)) {                                                         \
        (x);                                                                                       \
    }

// Sockinfo setsockopt() return values
// Internal socket option, should not pass request to OS.
#define SOCKOPT_INTERNAL_XLIO_SUPPORT 0
// Socket option was found but not supported, error should be returned to user.
#define SOCKOPT_NO_XLIO_SUPPORT -1
// Should pass to TCP/UDP level or OS.
#define SOCKOPT_PASS_TO_OS 1
// Pass the option also to the OS.
#define SOCKOPT_HANDLE_BY_OS -2

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

typedef enum { RX_READ = 23, RX_READV, RX_RECV, RX_RECVFROM, RX_RECVMSG } rx_call_t;

enum fd_type_t {
    FD_TYPE_SOCKET = 0,
    FD_TYPE_PIPE,
};

struct cmsg_state {
    struct msghdr *mhdr;
    struct cmsghdr *cmhdr;
    size_t cmsg_bytes_consumed;
};

struct buff_info_t {
    buff_info_t()
    {
        rx_reuse.set_id("buff_info_t (%p) : rx_reuse", this);
        n_buff_num = 0;
    }

    int n_buff_num;
    descq_t rx_reuse;
};

struct epoll_fd_rec {
    uint32_t events;
    epoll_data epdata;
    int offloaded_index; // offloaded fd index + 1

    epoll_fd_rec() { reset(); }

    void reset()
    {
        this->events = 0;
        memset(&this->epdata, 0, sizeof(this->epdata));
        this->offloaded_index = 0;
    }
};

struct net_device_resources_t {
    net_device_val *p_ndv;
    ring *p_ring;
    int refcnt;
};

struct fd_array_t {
    // coverity[member_decl]
    int fd_list[FD_ARRAY_MAX]; // Note: An FD might appear twice in the list,
    //  the user of this array will need to handle it correctly
    int fd_max;
    int fd_count;
};

struct ring_info_t {
    int refcnt;
    buff_info_t rx_reuse_info;
};

// This structure describes the send operation attributes
// Used attributes can be of different types TX_FILE, TX_WRITE, TX_WRITEV, TX_SEND, TX_SENDTO,
// TX_SENDMSG
struct xlio_tx_call_attr_t {
    struct _attr {
        struct iovec *iov;
        ssize_t sz_iov;
        int flags;
        socklen_t len;
        struct sockaddr *addr;
        const struct msghdr *hdr;
    } attr;

    pbuf_desc priv;
    tx_call_t opcode;

    ~xlio_tx_call_attr_t() {};
    void clear(void)
    {
        opcode = TX_UNDEF;
        memset(&attr, 0, sizeof(attr));
        memset(&priv, 0, sizeof(priv));
        priv.attr = PBUF_DESC_NONE;
    }

    xlio_tx_call_attr_t() { clear(); }
};

typedef std::unordered_map<ip_addr, net_device_resources_t> rx_net_device_map_t;
typedef xlio_list_t<mem_buf_desc_t, mem_buf_desc_t::buffer_node_offset> xlio_desc_list_t;
typedef std::unordered_map<flow_tuple_with_local_if, ring *> rx_flow_map_t;
typedef std::unordered_map<ring *, ring_info_t *> rx_ring_map_t;

// see route.c in Linux kernel
const uint8_t ip_tos2prio[16] = {0, 0, 0, 0, 2, 2, 2, 2, 6, 6, 6, 6, 4, 4, 4, 4};

// Forward declarations
class epfd_info;
class poll_group;
class entity_context;

class sockinfo {
public:
    enum sockinfo_state : uint16_t {
        SOCKINFO_UNDEFINED,
        SOCKINFO_OPENED,
        SOCKINFO_CLOSING,
        SOCKINFO_CLOSED,
        SOCKINFO_DESTROYING
    };

    static inline size_t pending_to_remove_node_offset(void)
    {
        return NODE_OFFSET(sockinfo, pending_to_remove_node);
    }

    static inline size_t socket_fd_list_node_offset(void)
    {
        return NODE_OFFSET(sockinfo, socket_fd_list_node);
    }

    static inline size_t ep_ready_fd_node_offset(void)
    {
        return NODE_OFFSET(sockinfo, ep_ready_fd_node);
    }

    static inline size_t ep_info_fd_node_offset(void)
    {
        return NODE_OFFSET(sockinfo, ep_info_fd_node);
    }

    sockinfo(int fd, int domain, bool use_ring_locks);
    virtual ~sockinfo();

    // Callback from lower layer notifying new receive packets
    // Return: 'true' if object queuing this receive packet
    //         'false' if not interested in this receive packet
    virtual bool rx_input_cb(mem_buf_desc_t *p_rx_pkt_mem_buf_desc_info,
                             void *pv_fd_ready_array) = 0;

    virtual void rx_data_recvd(uint32_t tot_size) = 0;
    virtual ssize_t tx(xlio_tx_call_attr_t &tx_arg) = 0;
    virtual void tx_thread_commit(mem_buf_desc_t *buf_list, uint32_t offset, uint32_t size,
                                  int flags) = 0;
    virtual bool is_readable(bool do_poll = true, fd_array_t *p_fd_array = nullptr) = 0;
    virtual bool is_writeable() = 0;
    virtual bool is_errorable(int *errors) = 0;
    virtual void clean_socket_obj() = 0;
    virtual void setPassthrough() = 0;
    virtual bool isPassthrough() = 0;
    virtual int prepareListen() = 0;
    virtual int shutdown(int __how) = 0;
    virtual int listen(int backlog) = 0;
    virtual int accept(struct sockaddr *__addr, socklen_t *__addrlen) = 0;
    virtual int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags) = 0;
    virtual int bind(const sockaddr *__addr, socklen_t __addrlen) = 0;
    virtual int connect(const sockaddr *__to, socklen_t __tolen) = 0;
    virtual void connect_entity_context() = 0;
    virtual void set_entity_context(entity_context *ctx) = 0;
    virtual int getsockname(sockaddr *__name, socklen_t *__namelen) = 0;
    virtual int getpeername(sockaddr *__name, socklen_t *__namelen) = 0;
    virtual int setsockopt(int __level, int __optname, __const void *__optval,
                           socklen_t __optlen) = 0;
    virtual int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen) = 0;
    virtual bool is_outgoing() = 0;
    virtual bool is_incoming() = 0;
    virtual bool is_closable() = 0;
    virtual void statistics_print(vlog_levels_t log_level = VLOG_DEBUG) = 0;
    virtual int fcntl(int __cmd, unsigned long int __arg);
    virtual int fcntl64(int __cmd, unsigned long int __arg);
    virtual int ioctl(unsigned long int __request, unsigned long int __arg);
    virtual fd_type_t get_type() = 0;

    virtual ssize_t rx(const rx_call_t call_type, iovec *iov, const ssize_t iovlen,
                       int *p_flags = 0, sockaddr *__from = nullptr, socklen_t *__fromlen = nullptr,
                       struct msghdr *__msg = nullptr) = 0;

    // Instructing the socket to immediately sample/un-sample the OS in receive flow
    virtual void set_immediate_os_sample() = 0;
    virtual void unset_immediate_os_sample() = 0;

    // In some cases we need the socket can't be deleted immidiatly
    //(for example STREAME sockets)
    // This prepares the socket for termination and return true if the
    // Return val: true is the socket is already closable and false otherwise
    virtual bool prepare_to_close(bool process_shutdown = false) = 0;
    virtual bool skip_os_select(); // true if fd must be skipped from OS select()

    inline bool set_flow_tag(uint32_t flow_tag_id);
    inline void sock_pop_descs_rx_ready(descq_t *cache);

    entity_context *get_entity_context() const { return m_entity_context; }
    uint32_t get_epoll_event_flags() { return m_epoll_event_flags; }
    uint32_t get_epoll_event_flags_thread() const { return m_epoll_event_flags_thread; }
    void set_epoll_event_flags(uint32_t events) { m_epoll_event_flags = events; }
    void set_epoll_event_flags_thread(uint32_t events) { m_epoll_event_flags_thread = events; }
    bool has_epoll_context() { return (!!m_econtext); }
    bool get_rx_pkt_ready_list_count() const { return m_n_rx_pkt_ready_list_count; }
    int get_fd() const { return m_fd; };
    sa_family_t get_family() { return m_family; }
    bool get_reuseaddr(void) { return m_reuseaddr; }
    bool get_reuseport(void) { return m_reuseport; }
    int get_rx_epfd(void) { return m_rx_epfd; }
    bool is_blocking(void) { return m_b_blocking; }
    bool flow_in_reuse(void) { return m_reuseaddr | m_reuseport; }
    bool is_shadow_socket_present() { return m_fd >= 0 && m_fd != m_rx_epfd; }
    uint32_t get_flow_tag_val() { return m_flow_tag_id; }
    in_protocol_t get_protocol(void) { return m_protocol; }
    socket_stats_t *get_sock_stats() const { return m_p_socket_stats; }
    rfs *get_rfs_ptr() const { return m_rfs_ptr; }
    void set_rfs_ptr(rfs *r) { m_rfs_ptr = r; }
    void destructor_helper();
    bool validate_and_convert_mapped_ipv4(sock_addr &sock) const;
    void consider_rings_migration_rx();
    int add_epoll_context(epfd_info *epfd);
    void remove_epoll_context(epfd_info *epfd);
    int get_epoll_context_fd();

    // Calling OS transmit
    ssize_t tx_os(const tx_call_t call_type, const iovec *p_iov, const ssize_t sz_iov,
                  const int __flags, const sockaddr *__to, const socklen_t __tolen);

#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    // This socket options copy is currently implemented for nginx and for very specific options.
    // This copy is called as part of fork() flow of nginx specifically.
    // If a generic fork() is implemented, this copy should be reimplemented in a more generic way,
    // see is_inherited_option mechanism of sockinfo_tcp for an example.
    void copy_sockopt_fork(const sockinfo *copy_from);
#if defined(DEFINED_NGINX)
    virtual void prepare_to_close_socket_pool(bool _push_pop) { NOT_IN_USE(_push_pop); }
    virtual void set_params_for_socket_pool() {};
    void set_rx_num_buffs_reuse(int val) { m_rx_num_buffs_reuse = val; }
#endif
#endif

    // XLIO Ultra API
    bool is_xlio_socket() const { return m_is_xlio_socket; }
    poll_group *get_poll_group() const { return m_p_group; }

protected:
    static const char *setsockopt_so_opt_to_str(int opt);

    virtual void lock_rx_q() = 0;
    virtual void unlock_rx_q() = 0;
    virtual void set_blocking(bool is_blocked);
    virtual mem_buf_desc_t *get_front_m_rx_pkt_ready_list() = 0;
    virtual size_t get_size_m_rx_pkt_ready_list() = 0;
    virtual void pop_front_m_rx_pkt_ready_list() = 0;
    virtual void push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff) = 0;
    virtual int rx_verify_available_data() = 0;
    virtual void update_header_field(data_updater *updater) = 0;
    virtual mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc) = 0;
    virtual mem_buf_desc_t *get_next_desc_peek(mem_buf_desc_t *p_desc,
                                               int &rx_pkt_ready_list_idx) = 0;
    virtual timestamps_t *get_socket_timestamps() = 0;
    virtual void update_socket_timestamps(timestamps_t *ts) = 0;
    virtual void post_dequeue() = 0;
    virtual int os_epoll_wait(epoll_event *ep_events, int maxevents);
    virtual void handle_ip_pktinfo(struct cmsg_state *cm_state) = 0;
    virtual bool try_un_offloading(); // un-offload the socket if possible

    virtual size_t handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                                    int *p_out_flags) = 0;

    // This callback will notify that socket is ready to receive and map the cq.
    virtual void rx_add_ring_cb(ring *p_ring);
    virtual void rx_del_ring_cb(ring *p_ring);

    inline void set_rx_reuse_pending(bool is_pending = true);
    inline void reuse_buffer(mem_buf_desc_t *buff);
    inline void save_strq_stats(uint32_t packet_strides);

    inline int dequeue_packet(iovec *p_iov, ssize_t sz_iov, sockaddr *__from, socklen_t *__fromlen,
                              int in_flags, int *p_out_flags);

    int get_sock_by_L3_L4(in_protocol_t protocol, const ip_address &ip, in_port_t port);
    void notify_epoll_context(uint32_t events);
    void save_stats_rx_os(int bytes);
    void save_stats_tx_os(int bytes);
    void save_stats_rx_offload(int nbytes);
    void socket_stats_init();
    bool attach_receiver(flow_tuple_with_local_if &flow_key);
    bool detach_receiver(flow_tuple_with_local_if &flow_key, rfs_rule **rule_extract = nullptr);
    net_device_resources_t *create_nd_resources(const ip_addr &ip_local);
    bool destroy_nd_resources(const ip_addr &ip_local);
    void do_rings_migration_rx(resource_allocation_key &old_key);
    int set_ring_attr(xlio_ring_alloc_logic_attr *attr);
    int set_ring_attr_helper(ring_alloc_logic_attr *sock_attr, xlio_ring_alloc_logic_attr *attr);
    void set_ring_logic_rx(ring_alloc_logic_attr ral);
    void set_ring_logic_tx(ring_alloc_logic_attr ral);
    void shutdown_rx();
    int modify_ratelimit(dst_entry *p_dst_entry, struct xlio_rate_limit_t &rate_limit);
    void move_descs(ring *p_ring, descq_t *toq, descq_t *fromq, bool own);
    void pop_descs_rx_ready(descq_t *cache, ring *p_ring = nullptr);
    void push_descs_rx_ready(descq_t *cache);
    void reuse_descs(descq_t *reuseq, ring *p_ring = nullptr);
    int set_sockopt_prio(__const void *__optval, socklen_t __optlen);
    bool ipv6_set_addr_sel_pref(int val);
    int ipv6_get_addr_sel_pref();
    inline void handle_recv_timestamping(struct cmsg_state *cm_state,
                                         timestamps_t *packet_timestamps);
    void insert_cmsg(struct cmsg_state *cm_state, int level, int type, void *data, int len);
    void handle_cmsg(struct msghdr *msg);
    void process_timestamps(mem_buf_desc_t *p_desc);
    void add_cqfd_to_sock_rx_epfd(ring *p_ring);
    void remove_cqfd_from_sock_rx_epfd(ring *p_ring);
    int os_wait_sock_rx_epfd(epoll_event *ep_events, int maxevents);
    void insert_epoll_event(uint64_t events);
    int handle_exception_flow();
    void rx_handle_cmsg(struct msghdr *msg, mem_buf_desc_t *out_buf);

    // Attach to all relevant rings for offloading receive flows - always used from slow path
    // According to bounded information we need to attach to all UC relevant flows
    // If local_ip is ANY then we need to attach to all offloaded interfaces OR to the one our
    // connected_ip is routed to
    bool attach_as_uc_receiver(role_t role, bool skip_rules = false);

    // Calling OS receive
    ssize_t rx_os(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, const int flags,
                  sockaddr *__from, socklen_t *__fromlen, struct msghdr *__msg);

    int setsockopt_kernel(int __level, int __optname, const void *__optval, socklen_t __optlen,
                          int supported, bool allow_priv);

    transport_t find_target_family(role_t role, const struct sockaddr *sock_addr_first,
                                   const struct sockaddr *sock_addr_second = nullptr);

private:
    int fcntl_helper(int __cmd, unsigned long int __arg, bool &bexit);
    bool attach_as_uc_receiver_anyip(sa_family_t family, role_t role, bool skip_rules);

    /**
     * @brief Update the RX ring fast-path pointer based on ring map size.
     *
     * This method maintains the m_p_rx_ring optimization pointer for single-ring sockets.
     * Performance optimization: When a socket has exactly one RX ring (the common case),
     * m_p_rx_ring provides direct pointer access, avoiding map iteration overhead.
     *
     * Must be called after any operation that modifies m_rx_ring_map:
     * - Adding rings (rx_add_ring_cb)
     * - Removing rings (rx_del_ring_cb)
     * - Ring migration (do_rings_migration_rx)
     */
    void update_rx_ring_ptr();

protected:
    dst_entry *m_p_connected_dst_entry = nullptr;
    sockinfo_state m_state = SOCKINFO_OPENED; // socket current state
    uint8_t m_n_tsing_flags = 0U;
    bool m_b_rcvtstamp = false;
    bool m_b_pktinfo = false;
    bool m_b_blocking = true;
    bool m_b_rcvtstampns = false;
    bool m_skip_cq_poll_in_rx;
    rfs *m_rfs_ptr = nullptr;
    socket_stats_t *m_p_socket_stats = nullptr;
    ring *m_p_rx_ring = nullptr; // used in TCP/UDP
    epfd_info *m_econtext = nullptr;
    entity_context *m_entity_context = nullptr;

    // End of first cache line

    uint32_t m_epoll_event_flags = 0U;
    uint32_t m_epoll_event_flags_thread = 0U;
    int m_n_rx_pkt_ready_list_count = 0;
    size_t m_rx_pkt_ready_offset = 0U;
    size_t m_rx_ready_byte_count = 0U;
    multilock m_app_lock;

public:
    list_node<sockinfo, sockinfo::ep_ready_fd_node_offset> ep_ready_fd_node;
    epoll_fd_rec m_fd_rec;
    wakeup_pipe m_sock_wakeup_pipe;

    // End of second cache 8 bytes ago

    list_node<sockinfo, sockinfo::socket_fd_list_node_offset> socket_fd_list_node;
    list_node<sockinfo, sockinfo::ep_info_fd_node_offset> ep_info_fd_node;
    list_node<sockinfo, sockinfo::pending_to_remove_node_offset> pending_to_remove_node;

protected:
    int m_rx_epfd;
    in_protocol_t m_protocol = PROTO_UNDEFINED;
    sa_family_t m_family;
    buff_info_t m_rx_reuse_buff; // used in TCP instead of m_rx_ring_map
    int m_fd; // identification information <socket fd>
    int m_rx_num_buffs_reuse;
    // used to periodically return buffers, even if threshold was not reached
    bool m_rx_reuse_buf_pending = false;
    // used to mark threshold was reached, but free was not done yet
    bool m_rx_reuse_buf_postponed = false;
    bool m_reuseaddr = false; // to track setsockopt with SO_REUSEADDR
    bool m_reuseport = false; // to track setsockopt with SO_REUSEPORT
    bool m_bind_no_port = false;
    bool m_is_ipv6only;
    uint8_t m_src_sel_flags = 0U;
    uint8_t m_n_uc_ttl_hop_lim;
    multilock m_lock_rcv;
    lock_mutex m_lock_snd;
    lock_mutex m_rx_migration_lock;
    sock_addr m_bound;
    sock_addr m_connected;
    ip_addr m_so_bindtodevice_ip;
    rx_net_device_map_t m_rx_nd_map;
    rx_flow_map_t m_rx_flow_map;
    rx_ring_map_t m_rx_ring_map; // CQ map
    lock_mutex_recursive m_rx_ring_map_lock;
    ring_allocation_logic_rx m_ring_alloc_logic_rx;
    loops_timer m_loops_timer;
    ring_alloc_logic_attr m_ring_alloc_log_rx;
    ring_alloc_logic_attr m_ring_alloc_log_tx;
    struct xlio_rate_limit_t m_so_ratelimit;
    uint32_t m_pcp = 0U;
    uint32_t m_flow_tag_id = 0U; // Flow Tag for this socket

    /*
     * XLIO Ultra API
     * TODO Move other Ultra API fields from sockinfo_tcp to sockinfo
     * TODO Move the fields to proper cold/hot sections in the final version.
     */

    // Polling group associated with this socket
    poll_group *m_p_group = nullptr;
    // Flag indicating if this is an XLIO socket
    bool m_is_xlio_socket = false;
    // Flag indicating if this is an XLIO socket terminat CB was called
    bool m_is_xlio_socket_terminated = false;

public:
#if defined(DEFINED_NGINX) || defined(DEFINED_ENVOY)
    bool m_is_for_socket_pool = false; // true when this fd will be used for socket pool on close
    int m_back_log = 0;
#endif
};

void sockinfo::set_rx_reuse_pending(bool is_pending)
{
    m_rx_reuse_buf_pending = is_pending;
}

bool sockinfo::set_flow_tag(uint32_t flow_tag_id)
{
    if (flow_tag_id && (flow_tag_id != FLOW_TAG_MASK)) {
        m_flow_tag_id = flow_tag_id;
        return true;
    }
    m_flow_tag_id = FLOW_TAG_MASK;
    return false;
}

void sockinfo::sock_pop_descs_rx_ready(descq_t *cache)
{
    lock_rx_q();
    mem_buf_desc_t *temp;
    const size_t size = get_size_m_rx_pkt_ready_list();
    if (size != 0 && m_rx_pkt_ready_offset != 0) {
        // Adjust the first pbuf by discarding the already read bytes
        temp = get_front_m_rx_pkt_ready_list();
        temp->lwip_pbuf.len -= m_rx_pkt_ready_offset;
        temp->lwip_pbuf.tot_len -= m_rx_pkt_ready_offset;
        temp->lwip_pbuf.payload = (uint8_t *)temp->lwip_pbuf.payload + m_rx_pkt_ready_offset;
        // Adjust iovec independently of lwip_pbuf; pbuf undefined for UDP
        temp->rx.frag.iov_len -= m_rx_pkt_ready_offset;
        temp->rx.frag.iov_base = (uint8_t *)temp->rx.frag.iov_base + m_rx_pkt_ready_offset;
        temp->rx.sz_payload -= m_rx_pkt_ready_offset;
    }
    for (size_t i = 0; i < size; i++) {
        temp = get_front_m_rx_pkt_ready_list();
        pop_front_m_rx_pkt_ready_list();
        cache->push_back(temp);
    }
    m_n_rx_pkt_ready_list_count = 0;
    m_rx_ready_byte_count = 0;
    m_rx_pkt_ready_offset = 0;
    if (m_p_socket_stats) {
        m_p_socket_stats->n_rx_ready_pkt_count = 0;
        m_p_socket_stats->n_rx_ready_byte_count = 0;
    }

    unlock_rx_q();
}

void sockinfo::save_strq_stats(uint32_t packet_strides)
{
    if (unlikely(m_p_socket_stats)) {
        m_p_socket_stats->counters.n_rx_packets++;
        m_p_socket_stats->strq_counters.n_strq_total_strides +=
            static_cast<uint64_t>(packet_strides);
        m_p_socket_stats->strq_counters.n_strq_max_strides_per_packet =
            std::max(m_p_socket_stats->strq_counters.n_strq_max_strides_per_packet, packet_strides);
    }
}

int sockinfo::dequeue_packet(iovec *p_iov, ssize_t sz_iov, sockaddr *__from, socklen_t *__fromlen,
                             int in_flags, int *p_out_flags)
{
    mem_buf_desc_t *pdesc;
    int total_rx = 0;
    uint32_t nbytes, pos;

    bool is_peek = in_flags & MSG_PEEK;
    int rx_pkt_ready_list_idx = 1;
    int rx_pkt_ready_offset = m_rx_pkt_ready_offset;

    pdesc = get_front_m_rx_pkt_ready_list();
    void *iov_base = (uint8_t *)pdesc->rx.frag.iov_base + m_rx_pkt_ready_offset;
    size_t bytes_left = pdesc->rx.frag.iov_len - m_rx_pkt_ready_offset;
    size_t payload_size = pdesc->rx.sz_payload;

    if (__from && __fromlen) {
        if (m_protocol == PROTO_UDP || m_connected.is_anyport()) {
            // For UDP non-connected or TCP listen socket fetch from packet.
            pdesc->rx.src.get_sa_by_family(__from, *__fromlen, m_family);
        } else {
            // For TCP connected 5T fetch from m_connected.
            // For TCP flow-tag we avoid filling packet with src for performance.
            m_connected.get_sa_by_family(__from, *__fromlen, m_family);
        }
    }

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

    if (unlikely(is_peek)) {
        // if MSG_PEEK is on, m_rx_pkt_ready_offset must be zero-ed
        m_rx_pkt_ready_offset = rx_pkt_ready_offset;
    } else {
        IF_STATS(m_p_socket_stats->n_rx_ready_byte_count -= total_rx);
        m_rx_ready_byte_count -= total_rx;
        post_dequeue();
        save_stats_rx_offload(total_rx);
    }

    total_rx = handle_msg_trunc(total_rx, payload_size, in_flags, p_out_flags);

    return total_rx;
}

void sockinfo::reuse_buffer(mem_buf_desc_t *buff)
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
        if (n_buff_num < m_rx_num_buffs_reuse) {
            return;
        }
        if (n_buff_num >= 2 * m_rx_num_buffs_reuse) {
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

#endif /* BASE_SOCKINFO_H */
