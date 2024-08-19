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

#ifndef XLIO_TYPES_H
#define XLIO_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

/*
 * Flags for recvfrom_zcopy()
 */
#define MSG_XLIO_ZCOPY_FORCE 0x01000000 // don't fallback to bcopy
#define MSG_XLIO_ZCOPY       0x00040000 // return: zero copy was done

/*
 * Options for setsockopt()/getsockopt()
 */
#define SO_XLIO_GET_API          2800
#define SO_XLIO_USER_DATA        2801
#define SO_XLIO_RING_ALLOC_LOGIC 2810
#define SO_XLIO_SHUTDOWN_RX      2821
#define SO_XLIO_PD               2822
#define SCM_XLIO_PD              SO_XLIO_PD
#define SCM_XLIO_NVME_PD         2823
#define SO_XLIO_EXT_VLAN_TAG     2824

/**
 * @def SO_XLIO_ISOLATE
 * Socket isolation option groups sockets under specified policy.
 *
 * Supported policies:
 *   - SO_XLIO_ISOLATE_DEFAULT - default behavior according to XLIO configuration.
 *
 *   - SO_XLIO_ISOLATE_SAFE - isolate sockets from the default sockets and guarantee thread
 *     safety regardless of XLIO configuration (note: this option doesn't change socket API
 *     thread safety model). This policy is mostly effective in XLIO_TCP_CTL_THREAD=delegate
 *     configuration.
 *
 * Current limitations:
 *   - SO_XLIO_ISOLATE option is supported only by TCP sockets
 *   - SO_XLIO_ISOLATE must be called according to thread safety model and XLIO configuration
 *   - SO_XLIO_ISOLATE may be called after socket() syscall and before either listen() or connect()
 */
#define SO_XLIO_ISOLATE         2825
#define SO_XLIO_ISOLATE_DEFAULT 0
#define SO_XLIO_ISOLATE_SAFE    1

enum { CMSG_XLIO_IOCTL_USER_ALLOC = 2900 };

/*
 * Flags for Dummy send API
 */
#define XLIO_SND_FLAGS_DUMMY MSG_SYN // equals to 0x400

/*
 * Return values for the receive packet notify callback function
 */
typedef enum {
    XLIO_PACKET_DROP, /* The library will drop the received packet and recycle
                        the buffer if no other socket needs it */

    XLIO_PACKET_RECV, /* The library will queue the received packet on this socket ready queue.
                        The application will read it with the usual recv socket APIs */

    XLIO_PACKET_HOLD /* Application will handle the queuing of the received packet. The application
                       must return the descriptor to the library using the free packet function
           But not in the context of XLIO's callback itself. */
} xlio_recv_callback_retval_t;

/**
 * @brief Pass this structure as an argument into getsockopt() with @ref SO_XLIO_PD
 * 	to get protection domain information from ring used for current socket.
 * 	This information can be available after setting connection for TX ring
 * 	and bounding to device for RX ring.
 * 	By default getting PD for TX ring.
 * 	This case can be used with sendmsg(SCM_XLIO_PD) when the data portion contains
 * 	an array of the elements with datatype as struct xlio_pd_key. Number of elements in this
 * 	array should be equal to msg_iovlen value. Every data pointer in msg_iov has
 * 	correspondent memory key.
 *
 * @param flags - to specify needed information.
 * @param pd - protection domain (PD) for the RDMA device context
 */
struct xlio_pd_attr {
    uint32_t flags;
    void *ib_pd;
};

/**
 * @brief elements with this datatype can be passed into sendmsg(SCM_XLIO_PD)
 * as control message with correspondent pointer to data.
 *
 * @param flags - to specify needed information. By default mkey value is used.
 * @param mkey - memory key
 */
struct xlio_pd_key {
    union {
        uint32_t flags;
        uint32_t message_length;
    };
    uint32_t mkey;
};

#define NVDA_NVME 666
#define NVME_TX   1
#define NVME_RX   2

enum {
    XLIO_NVME_DDGST_ENABLE = 1U << 31,
    XLIO_NVME_DDGST_OFFLOAD = 1U << 30,
    XLIO_NVME_HDGST_ENABLE = 1U << 29,
    XLIO_NVME_HDGST_OFFLOAD = 1U << 28,
    XLIO_NVME_PDA_MASK = ((1U << 4) - 1U),
    XLIO_NVME_DDGST_MASK = (XLIO_NVME_DDGST_ENABLE | XLIO_NVME_DDGST_OFFLOAD),
};

/************ SocketXtreme API types definition start***************/

enum {
    SOCKETXTREME_POLL_TX = (1 << 15),
};

enum {
    XLIO_SOCKETXTREME_PACKET = (1ULL << 32), /* New packet is available */
    XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED =
        (1ULL << 33) /* New connection is auto accepted by server */
};

/*
 * Represents specific buffer
 * Used in SocketXtreme extended API.
 */
struct xlio_buff_t {
    struct xlio_buff_t *next; /* next buffer (for last buffer next == NULL) */
    void *payload; /* pointer to data */
    uint16_t len; /* data length */
};

/**
 * Represents one specific packet
 * Used in SocketXtreme extended API.
 */
struct xlio_socketxtreme_packet_desc_t {
    size_t num_bufs; /* number of packet's buffers */
    uint16_t total_len; /* total data length */
    struct xlio_buff_t *buff_lst; /* list of packet's buffers */
    struct timespec hw_timestamp; /* packet hw_timestamp */
};

/*
 * Represents specific completion form.
 * Used in SocketXtreme extended API.
 */
struct xlio_socketxtreme_completion_t {
    /* Packet is valid in case XLIO_SOCKETXTREME_PACKET event is set
     */
    struct xlio_socketxtreme_packet_desc_t packet;
    /* Set of events
     */
    uint64_t events;
    /* User provided data.
     * By default this field has FD of the socket
     * User is able to change the content using setsockopt()
     * with level argument SOL_SOCKET and opname as SO_XLIO_USER_DATA
     */
    uint64_t user_data;
    /* Source address (in network byte order) set for:
     * XLIO_SOCKETXTREME_PACKET and XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED events
     */
    struct sockaddr_in src;
    /* Connected socket's parent/listen socket fd number.
     * Valid in case XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED event is set.
     */
    int listen_fd;
};

/************ SocketXtreme API types definition end ***************/

/**
 * Represents one packet
 * Used in receive zero-copy extended API.
 */
struct __attribute__((packed)) xlio_recvfrom_zcopy_packet_t {
    void *packet_id; // packet identifier
    size_t sz_iov; // number of fragments
    struct iovec iov[]; // fragments size+data
};

/**
 * Represents received packets
 * Used in receive zero-copy extended API.
 */
struct __attribute__((packed)) xlio_recvfrom_zcopy_packets_t {
    size_t n_packet_num; // number of received packets
    struct xlio_recvfrom_zcopy_packet_t pkts[]; // array of received packets
};

/*
 * Structure holding additional information on the packet and socket
 * Note: Check structure size value for future library changes
 */
struct __attribute__((packed)) xlio_info_t {
    size_t
        struct_sz; /* Compare this value with sizeof(xlio_info_t) to check version compatability */
    void *packet_id; /* Handle to received packet buffer to be return if zero copy logic is used */

    /* Packet addressing information (in network byte order) */
    const struct sockaddr *src;
    const struct sockaddr *dst;

    /* Packet information */
    size_t payload_sz;

    /* Socket's information */
    uint32_t socket_ready_queue_pkt_count; /* Current count of packets waiting to be read from the
                                              socket */
    uint32_t socket_ready_queue_byte_count; /* Current count of bytes waiting to be read from the
                                               socket */

    /* Packet timestamping information */
    struct timespec hw_timestamp;
    struct timespec sw_timestamp;
};

struct xlio_rate_limit_t {
    uint32_t rate; /* rate limit in Kbps */
    uint32_t max_burst_sz; /* maximum burst size in bytes */
    uint16_t typical_pkt_sz; /* typical packet size in bytes */
};

typedef enum {
    RING_LOGIC_PER_INTERFACE = 0, //!< RING_LOGIC_PER_INTERFACE
    RING_LOGIC_PER_IP = 1, //!< RING_LOGIC_PER_IP
    RING_LOGIC_PER_SOCKET = 10, //!< RING_LOGIC_PER_SOCKET
    RING_LOGIC_PER_USER_ID = 11, //!< RING_LOGIC_PER_USER_ID
    RING_LOGIC_PER_THREAD = 20, //!< RING_LOGIC_PER_THREAD
    RING_LOGIC_PER_CORE = 30, //!< RING_LOGIC_PER_CORE
    RING_LOGIC_PER_CORE_ATTACH_THREADS = 31, //!< RING_LOGIC_PER_CORE_ATTACH_THREADS
    RING_LOGIC_PER_OBJECT = 32, //!< RING_LOGIC_PER_OBJECT
    RING_LOGIC_ISOLATE = 33, //!< RING_LOGIC_ISOLATE
    RING_LOGIC_LAST //!< RING_LOGIC_LAST
} ring_logic_t;

typedef enum {
    XLIO_RING_ALLOC_MASK_RING_USER_ID = (1 << 0),
    XLIO_RING_ALLOC_MASK_RING_INGRESS = (1 << 1),
    XLIO_RING_ALLOC_MASK_RING_ENGRESS = (1 << 2),
} xlio_ring_alloc_logic_attr_comp_mask;

/**
 * @brief pass this struct to process by the library using setsockopt with
 * @ref SO_XLIO_RING_ALLOC_LOGIC
 * 	to set the allocation logic of this FD when he requests a ring.
 * 	@note ring_alloc_logic is a mandatory
 * @param comp_mask - what fields are read when processing this struct
 * 	see @ref xlio_ring_alloc_logic_attr_comp_mask
 * @param ring_alloc_logic- allocation ratio to use
 * @param user_idx - when used RING_LOGIC_PER_USER_ID int @ref ring_alloc_logic
 * 	this is the user id to define. This lets you define the same ring for
 * 	few FD's regardless the interface\thread\core.
 * @param ingress - RX ring
 * @param engress - TX ring
 */
struct xlio_ring_alloc_logic_attr {
    uint32_t comp_mask;
    ring_logic_t ring_alloc_logic;
    uint32_t user_id;
    uint32_t ingress : 1;
    uint32_t engress : 1;
    uint32_t reserved : 30;
};

/**
 *
 * Notification callback for incoming packet on socket
 * @param fd Socket's file descriptor which this packet refers to
 * @param iov iovector structure array point holding the packet
 *            received data buffer pointers and size of each buffer
 * @param iov_sz Size of iov array
 * @param xlio_info Additional information on the packet and socket
 * @param context User-defined value provided during callback
 *                registration for each socket
 *
 *   This callback function should be registered by the library calling
 * register_recv_callback() in the extended API. It can be unregistered by
 * setting a NULL function pointer. The library will call the callback to notify
 * of new incoming packets after the IP & UDP header processing and before
 * they are queued in the socket's receive queue.
 *   Context of the callback will always be from one of the user's application
 * threads when calling the following socket APIs: select, poll, epoll, recv,
 * recvfrom, recvmsg, read, readv.
 *
 * Notes:
 * - The application can call all of the Socket APIs control and send from
 *   within the callback context.
 * - Packet loss might occur depending on the applications behavior in the
 *   callback context.
 * - Parameters `iov' and `xlio_info' are only valid until callback context
 *   is returned to the library. User should copy these structures for later use
 *   if working with zero copy logic.
 */
typedef xlio_recv_callback_retval_t (*xlio_recv_callback_t)(int fd, size_t sz_iov,
                                                            struct iovec iov[],
                                                            struct xlio_info_t *xlio_info,
                                                            void *context);

/*
 * XLIO Socket API main objects
 */

typedef uintptr_t xlio_poll_group_t;
typedef uintptr_t xlio_socket_t;

struct xlio_buf {
    uint64_t userdata;
};

/*
 * XLIO Socket API callbacks
 */

/*
 * Memory callback.
 *
 * XLIO calls the callback each time XLIO allocates a memory region which can be used for RX
 * buffers. User can use this information to prepare the memory for some logic in the future.
 * Zerocopy RX interface provides pointers to such memory.
 *
 * Argument hugepage_size provides the page size if XLIO uses hugepages for the allocation.
 * If hugepage_size is not zero, the both addr and len are aligned to the page size boundary.
 * There is no alignment guarantee for regular pages and hugepage_size is zero in this case.
 * In case of external user allocator, XLIO reports hugepage_size zero regardless of the underlying
 * pages properties.
 */
typedef void (*xlio_memory_cb_t)(void *addr, size_t len, size_t hugepage_size);

/*
 * Socket event callback.
 *
 * May be called from xlio_poll_group_poll() context.
 * In the callback context, send operation is allowed only for the ESTABLISHED event.
 * Argument value holds the error code for the ERROR event and 0 for other events.
 *
 * List of possible error code values:
 * ECONNABORTED - connection aborted by local side
 * ECONNRESET - connection reset by remote side
 * ECONNREFUSED - connection refused by remote side during TCP handshake
 * ETIMEDOUT - connection timed out due to keepalive, user timeout option or TCP handshake timeout
 */
enum {
    /* TCP connection established. */
    XLIO_SOCKET_EVENT_ESTABLISHED = 1,
    /* Socket terminated and no further events are possible. */
    XLIO_SOCKET_EVENT_TERMINATED,
    /* Passive close. */
    XLIO_SOCKET_EVENT_CLOSED,
    /* An error occurred, see the error code value. */
    XLIO_SOCKET_EVENT_ERROR,
};
typedef void (*xlio_socket_event_cb_t)(xlio_socket_t, uintptr_t userdata_sq, int event, int value);

/*
 * Zerocopy completion event.
 *
 * May be called from the following contexts:
 *  - xlio_poll_group_poll() - likely
 *  - xlio_socket_send() - can happen only if data is flushed
 *  - xlio_socket_flush() / xlio_poll_group_flush()
 *  - xlio_socket_destroy()
 *
 * In the callback context, send operation is allowed unless the socket is under destruction.
 */
typedef void (*xlio_socket_comp_cb_t)(xlio_socket_t, uintptr_t userdata_sq, uintptr_t userdata_op);

/*
 * RX callback.
 *
 * Returns TCP payload upon arrival. Each call returns a single contiguous buffer. The buffer points
 * to memory within a block which is provided by the memory_cb() notification.
 *
 * xlio_buf is a descriptor of the buffer which must be returned to XLIO. During user ownership,
 * they may use the uninitialized field in the structure.
 */
typedef void (*xlio_socket_rx_cb_t)(xlio_socket_t, uintptr_t userdata_sq, void *data, size_t len,
                                    struct xlio_buf *buf);

typedef void (*xlio_socket_accept_cb_t)(xlio_socket_t sock, xlio_socket_t parent,
                                        uintptr_t parent_userdata_sq);

/*
 * XLIO Socket API attribute structures
 */

struct xlio_init_attr {
    unsigned flags;
    xlio_memory_cb_t memory_cb;

    /* Optional external user allocator for XLIO buffers. */
    void *(*memory_alloc)(size_t);
    void (*memory_free)(void *);
};

/* Sockets and rings will be protected with locks regardless of XLIO configuration. */
#define XLIO_GROUP_FLAG_SAFE 0x1
/* Group will keep dirty sockets to be flushed with xlio_poll_group_flush(). */
#define XLIO_GROUP_FLAG_DIRTY 0x2

struct xlio_poll_group_attr {
    unsigned flags;

    xlio_socket_event_cb_t socket_event_cb;
    xlio_socket_comp_cb_t socket_comp_cb;
    xlio_socket_rx_cb_t socket_rx_cb;
    xlio_socket_accept_cb_t socket_accept_cb;
};

struct xlio_socket_attr {
    unsigned flags;
    int domain; /* AF_INET or AF_INET6 */
    xlio_poll_group_t group;
    uintptr_t userdata_sq;
};

/* Flush socket after queueing the data. */
#define XLIO_SOCKET_SEND_FLAG_FLUSH 0x1
/* Copy user data to the internal buffers instead of taking ownership. */
#define XLIO_SOCKET_SEND_FLAG_INLINE 0x2

struct xlio_socket_send_attr {
    unsigned flags;
    uint32_t mkey;
    uintptr_t userdata_op;
};

#endif /* XLIO_TYPES_H */
