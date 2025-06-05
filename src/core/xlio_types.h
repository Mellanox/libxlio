/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_TYPES_H
#define XLIO_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

/*
 * Options for setsockopt()/getsockopt()
 */
#define SO_XLIO_GET_API          2800
#define SO_XLIO_RING_ALLOC_LOGIC 2810
#define SO_XLIO_SHUTDOWN_RX      2821
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
