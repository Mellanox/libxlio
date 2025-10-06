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
    RING_LOGIC_PER_INTERFACE = 0,
    RING_LOGIC_PER_IP = 1,
    RING_LOGIC_PER_SOCKET = 10,
    RING_LOGIC_PER_USER_ID = 11,
    RING_LOGIC_PER_THREAD = 20,
    RING_LOGIC_PER_CORE = 30,
    RING_LOGIC_PER_CORE_ATTACH_THREADS = 31,
    RING_LOGIC_PER_OBJECT = 32,
    RING_LOGIC_LAST
} ring_logic_t;

typedef enum {
    XLIO_RING_ALLOC_MASK_RING_USER_ID = (1 << 0),
    XLIO_RING_ALLOC_MASK_RING_INGRESS = (1 << 1),
    XLIO_RING_ALLOC_MASK_RING_ENGRESS = (1 << 2),
} xlio_ring_alloc_logic_attr_comp_mask;

/*
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

/*
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

/**
 * @addtogroup xlio_ultra_api XLIO Ultra API
 * @{
 */

/**
 * @brief Polling group handle
 * @ingroup xlio_poll_group
 *
 * Opaque handle representing a polling group for event management.
 */
typedef uintptr_t xlio_poll_group_t;

/**
 * @brief Socket handle
 * @ingroup xlio_socket
 *
 * Opaque handle representing an XLIO high-performance socket.
 */
typedef uintptr_t xlio_socket_t;

/**
 * @addtogroup xlio_rx
 * @{
 */

/**
 * @brief Buffer descriptor
 *
 * Opaque structure representing a receive buffer in zero-copy RX operations.
 * Buffers are provided via RX callbacks and must be returned to XLIO.
 *
 * @par Buffer Lifecycle:
 * 1. Buffer provided to application via xlio_socket_rx_cb_t
 * 2. Application processes data and optionally uses userdata field
 * 3. Application returns buffer via xlio_socket_buf_free() or xlio_poll_group_buf_free()
 *
 * @par User Data Field:
 * - Available for application use during buffer ownership
 * - Can be used for reference counting, linking, or other purposes
 * - Not initialized by XLIO
 *
 * @par Structure Members:
 * - uint64_t userdata: User data field available during buffer ownership
 */
struct xlio_buf {
    uint64_t userdata;
};

/** @} */ // end of xlio_rx group

/**
 * @defgroup xlio_callbacks Event Callbacks
 * @brief Callback functions for handling socket events
 *
 * The XLIO Ultra API uses callbacks to notify applications of various
 * events including connection state changes, data arrival, and completion
 * of zero-copy operations.
 *
 * Most of the callbacks are expected from the xlio_poll_group_poll() context.
 *
 * @{
 */

/**
 * @brief Memory allocation callback function
 *
 * This callback is invoked when XLIO allocates memory regions that
 * can be used for RX buffers. Applications can use this information
 * for memory management or preparation.
 *
 * @param addr Base address of the allocated memory
 * @param len Size of the allocated memory
 * @param hugepage_size Page size if hugepages are used, 0 for regular pages
 *
 * @note If hugepage_size is non-zero, both addr and len are aligned to
 * the page size boundary. For external allocators, hugepage_size is
 * always reported as zero.
 *
 * @see xlio_init_attr
 */
typedef void (*xlio_memory_cb_t)(void *addr, size_t len, size_t hugepage_size);

/** @brief Socket events */
enum {
    /** TCP connection established. */
    XLIO_SOCKET_EVENT_ESTABLISHED = 1,
    /** Socket terminated and no further events are possible. */
    XLIO_SOCKET_EVENT_TERMINATED,
    /** Passive close. */
    XLIO_SOCKET_EVENT_CLOSED,
    /** An error occurred, see the error code value. */
    XLIO_SOCKET_EVENT_ERROR,
};

/**
 * @brief Socket event callback function
 *
 * This callback is invoked when socket state changes occur, such as
 * connection establishment, errors, or termination.
 *
 * @param sock The socket generating the event
 * @param userdata_sq User data associated with the socket
 * @param event The event type (XLIO_SOCKET_EVENT_*)
 * @param value Event-specific value (error code for ERROR events, 0 otherwise)
 *
 * @par Event Types:
 * - XLIO_SOCKET_EVENT_ESTABLISHED: TCP connection established
 * - XLIO_SOCKET_EVENT_TERMINATED: Socket terminated, no further events
 * - XLIO_SOCKET_EVENT_CLOSED: Passive close by remote peer
 * - XLIO_SOCKET_EVENT_ERROR: Error occurred, see value for error code
 *
 * @par Error Codes (for ERROR events):
 * - ECONNABORTED: Connection aborted by local side
 * - ECONNRESET: Connection reset by remote side
 * - ECONNREFUSED: Connection refused during handshake
 * - ETIMEDOUT: Connection timed out
 *
 * @note Send operations are allowed only from the ESTABLISHED event context.
 *
 * @see xlio_poll_group_attr
 */
typedef void (*xlio_socket_event_cb_t)(xlio_socket_t sock, uintptr_t userdata_sq, int event,
                                       int value);

/**
 * @brief Zero-copy completion callback function
 *
 * This callback is invoked when a zero-copy send operation completes,
 * allowing the application to reclaim or reuse the transmitted buffers.
 *
 * @param sock The socket that completed the operation
 * @param userdata_sq User data associated with the socket
 * @param userdata_op User data associated with the specific operation
 *
 * @par Calling Contexts:
 * - xlio_poll_group_poll() (most common)
 * - xlio_socket_send() (if data is immediately flushed)
 * - xlio_socket_flush() / xlio_poll_group_flush()
 *
 * @note Send operations are allowed in this callback unless the socket
 * is being destroyed.
 *
 * @see xlio_socket_send_attr
 * @see xlio_poll_group_attr
 */
typedef void (*xlio_socket_comp_cb_t)(xlio_socket_t sock, uintptr_t userdata_sq,
                                      uintptr_t userdata_op);

/**
 * @brief Receive data callback function
 *
 * This callback is invoked when TCP payload arrives on a socket.
 * Each call provides a single contiguous buffer containing received data.
 *
 * @param sock The socket that received the data
 * @param userdata_sq User data associated with the socket
 * @param data Pointer to the received data
 * @param len Length of the received data
 * @param buf Buffer descriptor that must be returned via xlio_*_buf_free()
 *
 * @note The data pointer is valid only until the buffer is freed.
 * The buffer's userdata field can be used during user ownership.
 *
 * @see xlio_socket_buf_free()
 * @see xlio_poll_group_buf_free()
 * @see xlio_poll_group_attr
 */
typedef void (*xlio_socket_rx_cb_t)(xlio_socket_t sock, uintptr_t userdata_sq, void *data,
                                    size_t len, struct xlio_buf *buf);

/**
 * @brief Accept callback function
 *
 * This callback is invoked when a new connection is accepted on a
 * listening socket. The new socket is automatically created and
 * associated with the same polling group.
 *
 * @param sock The newly accepted socket
 * @param parent The listening socket that accepted the connection
 * @param parent_userdata_sq User data from the parent socket
 *
 * @note The new socket inherits the polling group from the parent but
 * may need additional configuration (e.g., userdata_sq update).
 *
 * @see xlio_socket_update()
 * @see xlio_poll_group_attr
 */
typedef void (*xlio_socket_accept_cb_t)(xlio_socket_t sock, xlio_socket_t parent,
                                        uintptr_t parent_userdata_sq);

/** @} */ // end of xlio_callbacks group

/**
 * @addtogroup xlio_init
 * @{
 */

/**
 * @brief XLIO initialization attributes
 *
 * Structure containing parameters for XLIO initialization with xlio_init_ex().
 *
 * @par Memory Management:
 * - memory_cb: Called when XLIO allocates memory regions for RX buffers
 * - memory_alloc/memory_free: Optional external allocator functions
 *
 * @par External Allocator Notes:
 * - When external allocator is provided, XLIO uses it instead of internal allocation
 * - Current implementation allocates a single memory block during xlio_init_ex()
 * - For external allocators, hugepage_size in memory_cb is always reported as zero
 *
 * @par Structure Members:
 * - unsigned flags: Initialization flags (reserved for future use)
 * - xlio_memory_cb_t memory_cb: Memory allocation notification callback
 * - void *(*memory_alloc)(size_t): Optional external memory allocator function
 * - void (*memory_free)(void *): Optional external memory deallocator function
 */
struct xlio_init_attr {
    unsigned flags;
    xlio_memory_cb_t memory_cb;

    /* Optional external user allocator for XLIO buffers. */
    void *(*memory_alloc)(size_t);
    void (*memory_free)(void *);
};

/** @} */ // end of xlio_init group

/**
 * @addtogroup xlio_poll_group
 * @{
 */

/** Sockets and rings will be protected with locks regardless of XLIO configuration. */
#define XLIO_GROUP_FLAG_SAFE 0x1
/** Group will keep dirty sockets to be flushed with xlio_poll_group_flush(). */
#define XLIO_GROUP_FLAG_DIRTY 0x2

/**
 * @brief Polling group attributes
 *
 * Structure containing configuration for a polling group creation and updates.
 * Event callbacks are registered per group, allowing different handling logic
 * for different types of connections.
 *
 * @par Required Callbacks:
 * - socket_event_cb: Must be provided (handles connection state changes)
 *
 * @par Optional Callbacks:
 * - socket_comp_cb: Zero-copy completion notifications
 * - socket_rx_cb: Receive data notifications
 * - socket_accept_cb: New connection acceptance (required for listening sockets)
 *
 * @par Structure Members:
 * - unsigned flags: Group flags (XLIO_GROUP_FLAG_*)
 * - xlio_socket_event_cb_t socket_event_cb: Socket event callback (required)
 * - xlio_socket_comp_cb_t socket_comp_cb: Zero-copy completion callback (optional)
 * - xlio_socket_rx_cb_t socket_rx_cb: Receive data callback (optional)
 * - xlio_socket_accept_cb_t socket_accept_cb: Accept callback for listening sockets (optional)
 */
struct xlio_poll_group_attr {
    unsigned flags;

    xlio_socket_event_cb_t socket_event_cb;
    xlio_socket_comp_cb_t socket_comp_cb;
    xlio_socket_rx_cb_t socket_rx_cb;
    xlio_socket_accept_cb_t socket_accept_cb;
};

/** @} */ // end of xlio_poll_group group

/**
 * @addtogroup xlio_socket
 * @{
 */

/**
 * @brief Socket creation attributes
 *
 * Structure containing parameters for socket creation with xlio_socket_create().
 * The socket is automatically associated with the specified polling group.
 *
 * @par Domain Support:
 * - AF_INET: IPv4 support
 * - AF_INET6: IPv6 support
 *
 * @par User Data:
 * - userdata_sq: Application-defined value for socket identification in callbacks
 * - Can be updated later with xlio_socket_update()
 *
 * @par Structure Members:
 * - unsigned flags: Socket flags (reserved for future use)
 * - int domain: Address family (AF_INET or AF_INET6)
 * - xlio_poll_group_t group: Polling group to associate socket with
 * - uintptr_t userdata_sq: User data for socket identification in callbacks
 */
struct xlio_socket_attr {
    unsigned flags;
    int domain; /* AF_INET or AF_INET6 */
    xlio_poll_group_t group;
    uintptr_t userdata_sq;
};

/** @} */ // end of xlio_socket group

/**
 * @addtogroup xlio_tx
 * @{
 */

/** Flush socket after queueing the data. */
#define XLIO_SOCKET_SEND_FLAG_FLUSH 0x1
/** Copy user data to the internal buffers instead of taking ownership. */
#define XLIO_SOCKET_SEND_FLAG_INLINE 0x2

/**
 * @brief Send operation attributes
 *
 * Structure containing parameters for send operations (xlio_socket_send/sendv).
 * Controls zero-copy behavior, flushing, and completion tracking.
 *
 * @par Zero-Copy Operation:
 * - mkey: Memory key for registered memory regions
 * - userdata_op: User data provided to completion callback
 * - For zero-copy, memory must be registered with ibv_pd from xlio_socket_get_pd()
 *
 * @par Inline vs Zero-Copy:
 * - INLINE flag: Data copied to internal buffers, no completion callback
 * - Zero-copy: Data sent directly from user buffer, completion callback invoked
 *
 * @par Structure Members:
 * - unsigned flags: Send flags (XLIO_SOCKET_SEND_FLAG_*)
 * - uint32_t mkey: Memory key for zero-copy operation (ignored for inline)
 * - uintptr_t userdata_op: User data for completion callback (zero-copy only)
 */
struct xlio_socket_send_attr {
    unsigned flags;
    uint32_t mkey;
    uintptr_t userdata_op;
};

/** @} */ // end of xlio_tx group

/** @} */ // end of xlio_ultra_api group

#endif /* XLIO_TYPES_H */
