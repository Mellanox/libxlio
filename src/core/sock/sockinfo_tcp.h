/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef TCP_SOCKINFO_H
#define TCP_SOCKINFO_H

#include "utils/lock_wrapper.h"
#include "proto/mem_buf_desc.h"
#include "sock/sockinfo.h"
#include "dev/buffer_pool.h"
#include "dev/cq_mgr_rx.h"
#include "xlio_extra.h"

#include "lwip/opt.h"
#include "lwip/tcp_impl.h"

#include "sockinfo.h"
#include "sockinfo_ulp.h"

/* Forward declarations */
struct xlio_socket_attr;
class poll_group;

#define BLOCK_THIS_RUN(blocking, flags) (blocking && !(flags & MSG_DONTWAIT))

/**
 * Tcp socket states: rdma_offload or os_passthrough. in rdma_offload:
 * init --/bind()/ --> bound -- /listen()/ --> accept_ready -- /accept()may go to connected/ -->
 * connected init --(optional: bind()/ -- /connect()|async_connect/--> connected --/close()/--> init
 * may need to handle bind before connect in the future
 */
enum tcp_sock_offload_e {
    TCP_SOCK_PASSTHROUGH = 1, // OS handling this socket connection
    //	TCP_SOCK_RDMA_CM,         // Offloaded, uses RDMA CM - SDP like connection
    TCP_SOCK_LWIP // Offloaded, uses LWIP for wire compatible TCP impl
};

enum tcp_sock_state_e {
    TCP_SOCK_INITED = 1,
    TCP_SOCK_BOUND_NO_PORT, // internal state that indicate that bind() called after
                            // IP_BIND_ADDRESS_NO_PORT, but before connect()
    TCP_SOCK_BOUND,
    TCP_SOCK_LISTEN_READY, // internal state that indicate that prepareListen was called
    TCP_SOCK_ACCEPT_READY,
    TCP_SOCK_CONNECTED_RD, // ready to rcv
    TCP_SOCK_CONNECTED_WR, // ready to send
    TCP_SOCK_CONNECTED_RDWR, // full duplex op
    TCP_SOCK_ASYNC_CONNECT, // async connect in progress
    TCP_SOCK_ACCEPT_SHUT // after shutdown on TCP_SOCK_ACCEPT_READY socket
};

/**
 * state machine for the connect() side connection establishment. Taken from VMS
 */
enum tcp_conn_state_e {
    TCP_CONN_INIT = 0,
    TCP_CONN_CONNECTING,
    TCP_CONN_CONNECTED,
    TCP_CONN_FAILED,
    TCP_CONN_TIMEOUT,
    TCP_CONN_ERROR,
    TCP_CONN_RESETED
};

enum xlio_express_flags : uint32_t {
    XLIO_EXPRESS_OP_TYPE_DESC,
    XLIO_EXPRESS_OP_TYPE_FILE_ZEROCOPY,
    XLIO_EXPRESS_OP_TYPE_MASK = 0x000fu,
    XLIO_EXPRESS_MSG_MORE,
    XLIO_EXPRESS_MSG_MASK = 0x00f0u,
};

struct socket_option_t {
    const int level;
    const int optname;
    const socklen_t optlen;
    void *optval;

    socket_option_t(const int _level, const int _optname, const void *_optval,
                    const socklen_t _optlen)
        : level(_level)
        , optname(_optname)
        , optlen(_optlen)
        , optval(malloc(optlen))
    {
        memcpy(optval, _optval, optlen);
    }

    ~socket_option_t()
    {
        if (optval) {
            free(optval);
        }
    }
};

class tcp_timers_collection : public timer_handler, public cleanable_obj {
public:
    tcp_timers_collection();
    tcp_timers_collection(int intervals);
    ~tcp_timers_collection() override;

    void clean_obj() override;

    void handle_timer_expired(void *user_data) override;

    void register_wakeup_event();

    void add_new_timer(sockinfo_tcp *sock);

    void remove_timer(sockinfo_tcp *sock);

    void set_group(poll_group *group) { m_p_group = group; }
    inline event_handler_manager *get_event_mgr();

private:
    void free_tta_resources();

protected:
    void *m_timer_handle = nullptr;

private:
    typedef std::list<sockinfo_tcp *> sock_list;
    typedef typename sock_list::iterator sock_list_itr;
    std::vector<sock_list> m_p_intervals;
    std::unordered_map<sockinfo_tcp *, std::tuple<uint32_t, sock_list_itr>> m_sock_remove_map;
    int m_n_intervals_size;
    int m_n_location = 0;
    int m_n_count = 0;
    int m_n_next_insert_bucket = 0;
    poll_group *m_p_group = nullptr;
};

class thread_local_tcp_timers : public tcp_timers_collection {
public:
    thread_local_tcp_timers();
    ~thread_local_tcp_timers() override;
};

extern tcp_timers_collection *g_tcp_timers_collection;

typedef std::deque<socket_option_t *> socket_options_list_t;
typedef std::map<tcp_pcb *, int> ready_pcb_map_t;
typedef std::map<flow_tuple, tcp_pcb *> syn_received_map_t;
typedef std::map<sock_addr, xlio_desc_list_t> peer_map_t;

/* taken from inet_ecn.h in kernel */
enum inet_ecns {
    INET_ECN_NOT_ECT = 0,
    INET_ECN_ECT_1 = 1,
    INET_ECN_ECT_0 = 2,
    INET_ECN_CE = 3,
    INET_ECN_MASK = 3,
};

class sockinfo_tcp : public sockinfo {
public:
    static inline size_t accepted_conns_node_offset()
    {
        return NODE_OFFSET(sockinfo_tcp, accepted_conns_node);
    }
    typedef xlio_list_t<sockinfo_tcp, sockinfo_tcp::accepted_conns_node_offset> sock_list_t;
    sockinfo_tcp(int fd, int domain);
    ~sockinfo_tcp() override;

    void clean_socket_obj() override;

    void setPassthrough(bool _isPassthrough)
    {
        m_sock_offload = _isPassthrough ? TCP_SOCK_PASSTHROUGH : TCP_SOCK_LWIP;
        IF_STATS(m_p_socket_stats->b_is_offloaded = !_isPassthrough);
    }
    void setPassthrough() override { setPassthrough(true); }
    bool isPassthrough() override { return m_sock_offload == TCP_SOCK_PASSTHROUGH; }

    int prepareListen() override;
    int shutdown(int __how) override;

    // Not always we can close immediately TCP socket: we can do that only after the TCP connection
    // in closed. In this method we just kikstarting the TCP connection termination (empty the
    // unsent/unacked, senf FIN...) Return val: true is the socket is already closable and false
    // otherwise
    bool prepare_to_close(bool process_shutdown = false) override;
    void create_dst_entry();
    void destructor_helper_tcp();
    bool prepare_dst_to_send(bool is_accepted_socket = false);

    int fcntl(int __cmd, unsigned long int __arg) override;
    int fcntl64(int __cmd, unsigned long int __arg) override;
    int ioctl(unsigned long int __request, unsigned long int __arg) override;
    int setsockopt(int __level, int __optname, const void *__optval, socklen_t __optlen) override;
    virtual int tcp_setsockopt(int __level, int __optname, const void *__optval,
                               socklen_t __optlen);
    int getsockopt(int __level, int __optname, void *__optval, socklen_t *__optlen) override;
    int getsockopt_offload(int __level, int __optname, void *__optval, socklen_t *__optlen);
    int connect(const sockaddr *, socklen_t) override;
    int bind(const sockaddr *__addr, socklen_t __addrlen) override;
    int listen(int backlog) override;
    int accept(struct sockaddr *__addr, socklen_t *__addrlen) override;
    int accept4(struct sockaddr *__addr, socklen_t *__addrlen, int __flags) override;
    int getsockname(sockaddr *__name, socklen_t *__namelen) override;
    int getpeername(sockaddr *__name, socklen_t *__namelen) override;
    void set_immediate_os_sample() override {};
    void unset_immediate_os_sample() override {};

    inline bool handle_bind_no_port(int &bind_ret, in_port_t in_port, const sockaddr *__addr,
                                    socklen_t __addrlen);
    inline void non_tcp_recved(int rx_len);

    void statistics_print(vlog_levels_t log_level = VLOG_DEBUG) override;

    inline struct tcp_pcb *get_pcb() { return &m_pcb; }

    inline unsigned sndbuf_available()
    {
        return static_cast<unsigned>(std::max(tcp_sndbuf(&m_pcb), 0));
    }

    inline unsigned get_mss() { return m_pcb.mss; }

    ssize_t tx(xlio_tx_call_attr_t &tx_arg) override;
    ssize_t tcp_tx(xlio_tx_call_attr_t &tx_arg);
    ssize_t rx(const rx_call_t call_type, iovec *p_iov, ssize_t sz_iov, int *p_flags,
               sockaddr *__from = nullptr, socklen_t *__fromlen = nullptr,
               struct msghdr *__msg = nullptr) override;
    static err_t ip_output(struct pbuf *p, struct tcp_seg *seg, void *v_p_conn, uint16_t flags);
    static err_t ip_output_syn_ack(struct pbuf *p, struct tcp_seg *seg, void *v_p_conn,
                                   uint16_t flags);
    static void tcp_state_observer(void *pcb_container, enum tcp_state new_state);
    static uint16_t get_route_mtu(struct tcp_pcb *pcb);

    void update_header_field(data_updater *updater) override;
    bool rx_input_cb(mem_buf_desc_t *p_rx_pkt_mem_buf_desc_info, void *pv_fd_ready_array) override;
    void abort_connection();
    void tcp_shutdown_rx();

    mem_buf_desc_t *tcp_tx_mem_buf_alloc(pbuf_type type);
    void tcp_rx_mem_buf_free(mem_buf_desc_t *p_desc);
    static struct pbuf *tcp_tx_pbuf_alloc(void *p_conn, pbuf_type type, pbuf_desc *desc,
                                          struct pbuf *p_buf);
    static void tcp_tx_pbuf_free(void *p_conn, struct pbuf *p_buff);
    static void tcp_rx_pbuf_free(struct pbuf *p_buff);
    static struct tcp_seg *tcp_seg_alloc_direct(void *p_conn);
    static struct tcp_seg *tcp_seg_alloc_cached(void *p_conn);
    static void tcp_seg_free_direct(void *p_conn, struct tcp_seg *seg);
    static void tcp_seg_free_cached(void *p_conn, struct tcp_seg *seg);
    uint32_t get_next_tcp_seqno() { return m_pcb.snd_lbb; }
    uint32_t get_next_tcp_seqno_rx() { return m_pcb.rcv_nxt; }

    mem_buf_desc_t *tcp_tx_zc_alloc(mem_buf_desc_t *p_desc);
    static void tcp_express_zc_callback(mem_buf_desc_t *p_desc);
    static void tcp_tx_zc_callback(mem_buf_desc_t *p_desc);
    void tcp_tx_zc_handle(mem_buf_desc_t *p_desc);

    bool is_readable(uint64_t *p_poll_sn, fd_array_t *p_fd_array = NULL) override;
    bool is_writeable() override;
    bool is_errorable(int *errors) override;
    bool is_closable() override
    {
        return get_tcp_state(&m_pcb) == CLOSED && m_syn_received.empty() &&
            m_accepted_conns.empty();
    }
    bool inline is_destroyable_lock()
    {
        bool state;
        m_tcp_con_lock.lock();
        state = get_tcp_state(&m_pcb) == CLOSED && m_state == SOCKINFO_CLOSING;
        m_tcp_con_lock.unlock();
        return state;
    }
    bool inline is_destroyable_no_lock()
    {
        return get_tcp_state(&m_pcb) == CLOSED && m_state == SOCKINFO_CLOSING;
    }
    bool skip_os_select() override
    {
        // calling os select on offloaded TCP sockets makes no sense unless it's a listen socket
        // to make things worse, it returns that os fd is ready...
        return (m_sock_offload == TCP_SOCK_LWIP && !is_server() && m_conn_state != TCP_CONN_INIT);
    }

    bool is_outgoing() override
    {
        const bool is_listen_socket = is_server() || get_tcp_state(&m_pcb) == LISTEN;
        // Excluding incoming and listen sockets we can determine outgoing sockets.
        return !m_b_incoming && !is_listen_socket;
    }

    bool is_incoming() override { return m_b_incoming; }
    bool is_timer_registered() const { return m_timer_registered; }
    void set_timer_registered(bool v) { m_timer_registered = v; }

    bool is_connected() { return m_sock_state == TCP_SOCK_CONNECTED_RDWR; }

    inline bool is_rtr()
    {
        return (m_n_rx_pkt_ready_list_count || m_sock_state == TCP_SOCK_CONNECTED_RD ||
                m_sock_state == TCP_SOCK_CONNECTED_RDWR);
    }

    bool is_rts()
    {
        // ready to send
        return m_sock_state == TCP_SOCK_CONNECTED_WR || m_sock_state == TCP_SOCK_CONNECTED_RDWR;
    }

    bool is_server()
    {
        return m_sock_state == TCP_SOCK_ACCEPT_READY || m_sock_state == TCP_SOCK_ACCEPT_SHUT;
    }

    void update_socket_timestamps(timestamps_t *ts) override { m_rx_timestamps = *ts; }

    inline fd_type_t get_type() override { return FD_TYPE_SOCKET; }

    void handle_timer_expired();

    inline ib_ctx_handler *get_ctx()
    {
        return m_p_connected_dst_entry ? m_p_connected_dst_entry->get_ctx() : nullptr;
    }

    inline ring *get_tx_ring() const noexcept
    {
        return m_p_connected_dst_entry ? m_p_connected_dst_entry->get_ring() : nullptr;
    }

    void rx_add_ring_cb(ring *p_ring) override;
    ring *get_rx_ring() { return m_p_rx_ring; }
    const flow_tuple_with_local_if &get_flow_tuple()
    {
        /* XXX Doesn't handle empty map and a map with multiple elements. */
        auto rx_flow_iter = m_rx_flow_map.begin();
        return rx_flow_iter->first;
    }

    void rx_poll_on_tx_if_needed()
    {
        if (m_sysvar_rx_poll_on_tx_tcp) {
            int poll_count = 0;
            rx_wait_helper(poll_count, false);
        }
    }

    /* Proxy to support ULP. TODO Refactor. */
    inline sockinfo_tcp_ops *get_ops() { return m_ops; }
    inline void set_ops(sockinfo_tcp_ops *ops) noexcept
    {
        std::swap(ops, m_ops);
        if (ops != m_ops_tcp) {
            delete ops;
        }
    }
    inline void reset_ops() noexcept { set_ops(m_ops_tcp); }

    bool is_utls_supported(int direction) const;

    inline int trylock_tcp_con() { return m_tcp_con_lock.trylock(); }
    inline void lock_tcp_con() { m_tcp_con_lock.lock(); }
    inline void unlock_tcp_con() { m_tcp_con_lock.unlock(); }
    tcp_timers_collection *get_tcp_timer_collection();
    bool is_cleaned() const { return m_is_cleaned; }
    static err_t rx_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    static err_t rx_drop_lwip_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);

    int tcp_tx_express(const struct iovec *iov, unsigned iov_len, uint32_t mkey, unsigned flags,
                       void *opaque_op);
    int tcp_tx_express_inline(const struct iovec *iov, unsigned iov_len, unsigned flags);
    void flush();

    void set_xlio_socket(const struct xlio_socket_attr *attr);
    void add_tx_ring_to_group();
    bool is_xlio_socket() { return m_p_group != nullptr; }
    poll_group *get_poll_group() { return m_p_group; }
    void xlio_socket_event(int event, int value);
    static err_t rx_lwip_cb_xlio_socket(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
    static void err_lwip_cb_xlio_socket(void *pcb_container, err_t err);

protected:
    void lock_rx_q() override;
    void unlock_rx_q() override;
    bool try_un_offloading() override; // un-offload the socket if possible
    int os_epoll_wait(epoll_event *ep_events, int maxevents) override;

    size_t handle_msg_trunc(size_t total_rx, size_t payload_size, int in_flags,
                            int *p_out_flags) override;

private:
    int fcntl_helper(int __cmd, unsigned long int __arg, bool &bexit);
    void get_tcp_info(struct tcp_info *ti);

    inline void lwip_pbuf_init_custom(mem_buf_desc_t *p_desc);

    void tcp_timer();
    bool poll_and_progress_rx(uint64_t &poll_sn);
    bool check_last_rx_poll_progress(unsigned int prev_sndbuf, bool all_drained);
    bool prepare_listen_to_close();

    // Builds rfs key
    static void create_flow_tuple_key_from_pcb(flow_tuple &key, struct tcp_pcb *pcb);

    // accept cb func
    static err_t accept_lwip_cb(void *arg, struct tcp_pcb *child_pcb, err_t err);

    // Called when legal syn is received in order to remember the new active pcb which
    // is already created by lwip, but no sockinfo instance is created yet at this stage
    static err_t syn_received_lwip_cb(void *arg, struct tcp_pcb *newpcb);
    static err_t syn_received_timewait_cb(void *arg, struct tcp_pcb *newpcb);

    static err_t syn_received_drop_lwip_cb(void *arg, struct tcp_pcb *newpcb);

    static err_t clone_conn_cb(void *arg, struct tcp_pcb **newpcb);

    // Called by L3_level_tcp_input to unlock a new pcb/socket.
    // @param newpcb The new pcb. Can be nullptr.
    static void accepted_pcb_cb(struct tcp_pcb *newpcb);

    int accept_helper(struct sockaddr *__addr, socklen_t *__addrlen, int __flags = 0);

    // clone socket in accept call
    sockinfo_tcp *accept_clone();
    // connect() helper & callback func
    int wait_for_conn_ready_blocking();
    static err_t connect_lwip_cb(void *arg, struct tcp_pcb *tpcb, err_t err);
    // tx
    unsigned tx_wait(bool blocking);
    int os_epoll_wait_with_tcp_timers(epoll_event *ep_events, int maxevents);
    void handle_incoming_handshake_failure(sockinfo_tcp *child_conn);

    // rx
    // int rx_wait(int &poll_count, bool blocking = true);
    static err_t ack_recvd_lwip_cb(void *arg, struct tcp_pcb *tpcb, u16_t space);

    ssize_t tcp_tx_handle_done_and_unlock(ssize_t total_tx, int errno_tmp, bool is_dummy,
                                          bool is_send_zerocopy);
    ssize_t tcp_tx_handle_errno_and_unlock(int error_number);
    ssize_t tcp_tx_handle_partial_send_and_unlock(ssize_t total_tx, int errno_to_report,
                                                  bool is_dummy, bool is_send_zerocopy,
                                                  int errno_to_restore);
    ssize_t tcp_tx_handle_sndbuf_unavailable(ssize_t total_tx, bool is_dummy, bool is_send_zerocopy,
                                             int errno_to_restore);
    ssize_t tcp_tx_slow_path(xlio_tx_call_attr_t &tx_arg);
    err_t handle_fin(struct tcp_pcb *pcb, err_t err);
    void handle_rx_lwip_cb_error(pbuf *p);
    void rx_lwip_cb_error(pbuf *p);
    inline void rx_lwip_process_chained_pbufs(pbuf *p);
    inline void rx_lwip_shrink_rcv_wnd(size_t pbuf_tot_len, int nbytes);
    inline void save_packet_info_in_ready_list(pbuf *p);
    // Be sure that m_pcb is initialized
    void set_conn_properties_from_pcb();
    void set_sock_options(sockinfo_tcp *new_sock);
    void passthrough_unlock(const char *dbg);
    // Register to timer
    void register_timer();

    void handle_socket_linger();

    /*
     * Supported only for UDP
     */
    void handle_ip_pktinfo(struct cmsg_state *) override {};

    int handle_rx_error(bool blocking);

    /** Function prototype for tcp error callback functions. Called when the pcb
     * receives a RST or is unexpectedly closed for any other reason.
     *
     * @note The corresponding pcb is already freed when this callback is called!
     *
     * @param arg Additional argument to pass to the callback function (@see tcp_arg())
     * @param err Error code to indicate why the pcb has been closed
     *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
     *            ERR_RST: the connection was reset by the remote host
     */
    static void err_lwip_cb(void *arg, err_t err);

    // TODO: it is misleading to declare inline in file that doesn't contain the implementation as
    // it can't help callers
    inline void return_pending_rx_buffs();
    inline void return_pending_tx_buffs();
    inline void reuse_buffer(mem_buf_desc_t *buff);
    mem_buf_desc_t *get_next_desc(mem_buf_desc_t *p_desc) override;
    mem_buf_desc_t *get_next_desc_peek(mem_buf_desc_t *p_desc, int &rx_pkt_ready_list_idx) override;
    timestamps_t *get_socket_timestamps() override;

    inline void return_reuse_buffers_postponed()
    {
        if (!m_rx_reuse_buf_postponed) {
            return;
        }

        // for the parallel reclaim mechanism from internal thread, used for "silent" sockets
        set_rx_reuse_pending(false);

        m_rx_reuse_buf_postponed = false;

        if (m_p_rx_ring) {
            if (m_rx_reuse_buff.n_buff_num >= m_rx_num_buffs_reuse) {
                if (m_p_rx_ring->reclaim_recv_buffers(&m_rx_reuse_buff.rx_reuse)) {
                    m_rx_reuse_buff.n_buff_num = 0;
                } else {
                    m_rx_reuse_buf_postponed = true;
                }
            }
        } else {
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
    }

    void post_dequeue() override {};

    // Returns the connected pcb, with 5 tuple which matches the input arguments,
    // in state "SYN Received" or NULL if pcb wasn't found
    struct tcp_pcb *get_syn_received_pcb(const flow_tuple &key) const;
    struct tcp_pcb *get_syn_received_pcb(const sock_addr &src, const sock_addr &dst);

    mem_buf_desc_t *get_front_m_rx_pkt_ready_list() override;
    size_t get_size_m_rx_pkt_ready_list() override;
    void pop_front_m_rx_pkt_ready_list() override;
    void push_back_m_rx_pkt_ready_list(mem_buf_desc_t *buff) override;

    // lock_spin_recursive m_rx_cq_lck;
    /* pick all cqs that match given address */
    int rx_verify_available_data() override;
    inline int rx_wait(int &poll_count, bool blocking);
    inline int rx_wait_lockless(int &poll_count, bool blocking);
    int rx_wait_helper(int &poll_count, bool blocking);
    void fit_rcv_wnd(bool force_fit);
    void fit_snd_bufs(unsigned int new_max);

    inline struct tcp_seg *get_tcp_seg_cached();
    inline struct tcp_seg *get_tcp_seg_direct();
    inline void put_tcp_seg_cached(struct tcp_seg *seg);
    inline void put_tcp_seg_direct(struct tcp_seg *seg);
    inline void return_tcp_segs(struct tcp_seg *seg);

    void queue_rx_ctl_packet(struct tcp_pcb *pcb, mem_buf_desc_t *p_desc);
    bool process_peer_ctl_packets(xlio_desc_list_t &peer_packets);
    void process_my_ctl_packets();
    void process_children_ctl_packets();
    void process_reuse_ctl_packets();
    void process_rx_ctl_packets();
    static void put_agent_msg(void *arg);
    bool is_connected_and_ready_to_send();

    inline event_handler_manager *get_event_mgr();

public:
    static const int CONNECT_DEFAULT_TIMEOUT_MS = 10000;

    list_node<sockinfo_tcp, sockinfo_tcp::accepted_conns_node_offset> accepted_conns_node;

private:
    sockinfo_tcp_ops *m_ops;
    sockinfo_tcp_ops *m_ops_tcp;

    // lwip specific things
    struct tcp_pcb m_pcb;
    fd_array_t *m_iomux_ready_fd_array;
    socket_options_list_t m_socket_options_list;
    timestamps_t m_rx_timestamps;
    tcp_sock_offload_e m_sock_offload;
    tcp_sock_state_e m_sock_state;
    sockinfo_tcp *m_parent;
    // received packet source (true if its from internal thread)
    bool m_b_incoming;
    bool m_b_attached;
    bool m_timer_registered = false;
    /* connection state machine */
    int m_conn_timeout;
    /* RCVBUF acconting */
    int m_rcvbuff_max;
    int m_rcvbuff_current;
    int m_rcvbuff_non_tcp_recved;
    tcp_conn_state_e m_conn_state;
    struct linger m_linger;

    /* local & peer addresses */
    /*	struct sockaddr *m_addr_local;
        socklen_t m_local_alen;
        struct sockaddr *m_addr_peer;
        socklen_t m_peer_alen;
    */

    // Relevant only for listen sockets: map connections in syn received state
    // We need this map since for syn received connection no sockinfo is created yet!
    syn_received_map_t m_syn_received;

    /* pending connections */
    sock_list_t m_accepted_conns;

    uint32_t m_ready_conn_cnt;
    int m_backlog;

    multilock m_tcp_con_lock;

    // used for reporting 'connected' on second non-blocking call to connect or
    // second call to failed connect blocking socket.
    bool report_connected;
    bool m_is_cleaned = false; // If this socket registered deletion on internal thread.
    int m_error_status;

    const buffer_batching_mode_t m_sysvar_buffer_batching_mode;
    const uint32_t m_sysvar_tx_segs_batch_tcp;

    struct tcp_seg *m_tcp_seg_list;
    uint32_t m_tcp_seg_count;
    uint32_t m_tcp_seg_in_use;

    xlio_desc_list_t m_rx_pkt_ready_list;
    lock_spin_recursive m_rx_ctl_packets_list_lock;
    tscval_t m_last_syn_tsc;
    xlio_desc_list_t m_rx_ctl_packets_list;
    peer_map_t m_rx_peer_packets;
    xlio_desc_list_t m_rx_ctl_reuse_list;
    ready_pcb_map_t m_ready_pcbs;
    static const unsigned TX_CONSECUTIVE_EAGAIN_THREASHOLD = 10;
    unsigned m_tx_consecutive_eagain_count;
    bool m_sysvar_rx_poll_on_tx_tcp;
    uint64_t m_user_huge_page_mask;
    uint16_t m_external_vlan_tag = 0U;
    /*
     * Storage API
     * TODO Move the fields to proper cold/hot sections in the final version.
     */
    bool m_b_xlio_socket_dirty = false;
    uintptr_t m_xlio_socket_userdata = 0;
    poll_group *m_p_group = nullptr;
};

#endif
