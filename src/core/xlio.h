/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef XLIO_H
#define XLIO_H

#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "xlio_types.h"

#ifdef __cplusplus
extern "C" {
#endif

int xlio_socket(int __domain, int __type, int __protocol);

int xlio_close(int __fd);

int xlio_shutdown(int __fd, int __how);

int xlio_listen(int __fd, int backlog);

int xlio_accept(int __fd, struct sockaddr *__addr, socklen_t *__addrlen);

int xlio_accept4(int __fd, struct sockaddr *__addr, socklen_t *__addrlen, int __flags);

int xlio_bind(int __fd, const struct sockaddr *__addr, socklen_t __addrlen);

int xlio_connect(int __fd, const struct sockaddr *__to, socklen_t __tolen);

int xlio_setsockopt(int __fd, int __level, int __optname, __const void *__optval,
                    socklen_t __optlen);

int xlio_getsockopt(int __fd, int __level, int __optname, void *__optval, socklen_t *__optlen);

int xlio_fcntl(int __fd, int __cmd, ...);

int xlio_fcntl64(int __fd, int __cmd, ...);

int xlio_getsockname(int __fd, struct sockaddr *__name, socklen_t *__namelen);

int xlio_getpeername(int __fd, struct sockaddr *__name, socklen_t *__namelen);

ssize_t xlio_read(int __fd, void *__buf, size_t __nbytes);

ssize_t xlio_readv(int __fd, const struct iovec *iov, int iovcnt);

ssize_t xlio_recv(int __fd, void *__buf, size_t __nbytes, int __flags);

ssize_t xlio_recvmsg(int __fd, struct msghdr *__msg, int __flags);

struct mmsghdr;

int xlio_recvmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags,
                  const struct timespec *__timeout);

ssize_t xlio_recvfrom(int __fd, void *__buf, size_t __nbytes, int __flags, struct sockaddr *__from,
                      socklen_t *__fromlen);

ssize_t xlio_write(int __fd, __const void *__buf, size_t __nbytes);

ssize_t xlio_writev(int __fd, const struct iovec *iov, int iovcnt);

ssize_t xlio_send(int __fd, __const void *__buf, size_t __nbytes, int __flags);

ssize_t xlio_sendmsg(int __fd, __const struct msghdr *__msg, int __flags);

int xlio_sendmmsg(int __fd, struct mmsghdr *__mmsghdr, unsigned int __vlen, int __flags);

ssize_t xlio_sendto(int __fd, __const void *__buf, size_t __nbytes, int __flags,
                    const struct sockaddr *__to, socklen_t __tolen);

ssize_t xlio_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

ssize_t xlio_sendfile64(int out_fd, int in_fd, __off64_t *offset, size_t count);

int xlio_select(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__exceptfds,
                struct timeval *__timeout);

int xlio_pselect(int __nfds, fd_set *__readfds, fd_set *__writefds, fd_set *__errorfds,
                 const struct timespec *__timeout, const sigset_t *__sigmask);
int xlio_poll(struct pollfd *__fds, nfds_t __nfds, int __timeout);

int xlio_ppoll(struct pollfd *__fds, nfds_t __nfds, const struct timespec *__timeout,
               const sigset_t *__sigmask);

int xlio_epoll_create(int __size);

int xlio_epoll_create1(int __flags);

int xlio_epoll_ctl(int __epfd, int __op, int __fd, struct epoll_event *__event);

int xlio_epoll_wait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout);

int xlio_epoll_pwait(int __epfd, struct epoll_event *__events, int __maxevents, int __timeout,
                     const sigset_t *__sigmask);
int xlio_socketpair(int __domain, int __type, int __protocol, int __sv[2]);

int xlio_pipe(int __filedes[2]);

int xlio_open(__const char *__file, int __oflag, ...);

int xlio_creat(const char *__pathname, mode_t __mode);

int xlio_dup(int __fd);

int xlio_dup2(int __fd, int __fd2);

/*
 * Add a libxlio.conf rule to the top of the list.
 * This rule will not apply to existing sockets which already considered the conf rules.
 * (around connect/listen/send/recv ..)
 * @param config_line A char buffer with the exact format as defined in libxlio.conf, and should
 * end with '\0'.
 * @return 0 on success, or error code on failure.
 */
int xlio_add_conf_rule(const char *config_line);

/*
 * Create sockets on pthread tid as offloaded/not-offloaded.
 * This does not affect existing sockets.
 * Offloaded sockets are still subject to libxlio.conf rules.
 * @param offload 1 for offloaded, 0 for not-offloaded.
 * @return 0 on success, or error code on failure.
 */
int xlio_thread_offload(int offload, pthread_t tid);

/*
 * Dump fd statistics using the library logger.
 * @param fd to dump, 0 for all open fds.
 * @param log_level dumping level corresponding vlog_levels_t enum (vlogger.h).
 * @return 0 on success, or error code on failure.
 */
int xlio_dump_fd_stats(int fd, int log_level);

/**
 * Register a received packet notification callback.
 *
 * @param s Socket file descriptor.
 * @param callback Callback function.
 * @param context user contex for callback function.
 * @return 0 - success, -1 - error
 *
 * errno is set to: EINVAL - not offloaded socket
 */
int xlio_register_recv_callback(int s, xlio_recv_callback_t callback, void *context);

/**
 * @defgroup xlio_socket_api XLIO Socket API
 * @brief High-performance zero-copy networking interface
 *
 * The XLIO Socket API is a performance-oriented, event-based networking interface
 * designed for applications requiring maximum throughput and minimal latency.
 * It provides zero-copy capabilities and efficient memory management for
 * high-performance networking.
 *
 * @section features Key Features
 * - Zero-copy receive and transmit operations
 * - Event-driven architecture with callbacks
 * - Memory management with user-provided allocators
 * - TCP socket abstraction with non-blocking operations
 * - Polling groups for efficient event handling
 * - Support for both IPv4 and IPv6
 *
 * @section architecture Architecture Overview
 * The API is built around three main concepts:
 * 1. **Polling Groups**: Event management and callback registration
 * 2. **Sockets**: TCP socket abstraction with zero-copy capabilities
 * 3. **Buffers**: Memory management for zero-copy operations
 *
 * @section workflow Typical Workflow
 * 1. Initialize XLIO with xlio_init_ex()
 * 2. Create polling group with xlio_poll_group_create()
 * 3. Create socket with xlio_socket_create()
 * 4. Configure socket (bind, connect, listen)
 * 5. Poll for events with xlio_poll_group_poll()
 * 6. Handle events via registered callbacks
 * 7. Send/receive data using zero-copy operations
 * 8. Clean up resources
 *
 * @section concurrency Concurrency and Thread Safety
 * The XLIO Ultra API is designed for high-performance applications with specific
 * concurrency patterns and thread safety requirements.
 *
 * @subsection thread_safety Thread Safety Model
 * - **The API is NOT thread-safe by default**
 * - Applications are responsible for proper serialization when accessing
 *   XLIO objects from multiple threads
 * - No internal locking is provided to maximize performance
 *
 * @subsection polling_group_concurrency Polling Group Concurrency
 * Polling groups are the primary mechanism for achieving concurrency:
 * - **Multiple polling groups can be polled concurrently** from different threads
 * - **Polling groups do not share resources** with each other
 * - **Sockets from different groups can be handled concurrently** without serialization
 *
 * @subsection serialization_requirements Serialization Requirements
 * - **Within a polling group**: All operations require serialization
 *   - Only one thread should call xlio_poll_group_poll() per group at a time
 *   - Socket operations within the same group must be serialized
 *   - Serialized polling group and socket calls can be executed by different threads
 * - **Across polling groups**: No serialization required
 *   - Different threads can operate on different groups simultaneously
 *
 * @subsection thread_safety_exceptions Thread Safety Exceptions
 * Some operations have specific thread safety characteristics:
 * - **Initialization**: xlio_init_ex() and xlio_exit() are not thread-safe
 * - A group created with the flag XLIO_GROUP_FLAG_SAFE can execute a polling and socket TX
 *   operations concurrently
 *
 * @section limitations Current Limitations
 * - TCP sockets only (no UDP support)
 * - No bonding support
 * - Only busy polling is supported
 * - fork() is supported only without created polling groups
 * @{
 */

/**
 * @defgroup xlio_init Initialization and Cleanup
 * @brief Functions for initializing and cleaning up the XLIO Socket API
 * @{
 */

/* Forward declaration. */
struct ibv_pd;

/**
 * @brief Initialize the XLIO Socket API
 *
 * This function must be called before using any other XLIO Socket API functions.
 * It's a heavy operation that sets up the internal state, allocates resources,
 * and configures the system for high-performance networking.
 *
 * @note This function is not thread-safe. However, subsequent serialized calls
 * will exit successfully without performing any action.
 *
 * @param attr Initialization attributes structure
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid parameters
 * - ENOMEM: Insufficient memory
 * - ENODEV: No compatible network devices found
 *
 * @see xlio_exit()
 * @see xlio_init_attr
 */
int xlio_init_ex(const struct xlio_init_attr *attr);

/**
 * @brief Initialize XLIO
 *
 * This function is similar to xlio_init_ex() but doesn't accept additional
 * attributes.
 *
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid parameters
 * - ENOMEM: Insufficient memory
 * - ENODEV: No compatible network devices found
 *
 * @see xlio_exit()
 */
int xlio_init(void);

/**
 * @brief Finalize XLIO
 *
 * Finalizes and cleans XLIO resources.
 *
 * @return 0 on success, -1 on error (errno is set)
 */
int xlio_exit(void);

/** @} */ // end of xlio_init group

/**
 * @defgroup xlio_poll_group Polling Groups
 * @brief Functions for managing polling groups and event handling
 *
 * Polling groups are the core event management mechanism in the XLIO Socket API.
 * They allow applications to register event callbacks and efficiently poll for
 * network events across multiple sockets.
 *
 * Polling group is a collection of sockets and resources required for their operation.
 * Different polling groups can be used concurrently without serialization.
 *
 * Polling groups provide loggical sockets organization for the following purposes:
 *  - Achieving concurrency and scaling
 *  - Implementing different RX / completion logic
 *
 * Recommendations:
 *  - Groups are expected to be long lived objects. Frequent creation/destruction has a penalty.
 *  - Reduce the number of different network interfaces within a group to minimum. This will
 *    optimize the HW objects utilization. However, maintaining extra groups can have an overhead.
 *
 * @{
 */

/**
 * @brief Create a new polling group
 *
 * Creates a new polling group with the specified attributes. Event callbacks
 * are registered per group, allowing applications to implement different
 * handling logic for different types of connections.
 *
 * @param attr Polling group attributes
 * @param group_out Pointer to store the created group handle
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid parameters (group_out is NULL, attr is NULL, or socket_event_cb is NULL)
 * - ENOMEM: Insufficient memory
 *
 * @note socket_event_cb is mandatory.
 *
 * @see xlio_poll_group_destroy()
 * @see xlio_poll_group_attr
 */
int xlio_poll_group_create(const struct xlio_poll_group_attr *attr, xlio_poll_group_t *group_out);

/**
 * @brief Destroy a polling group
 *
 * Destroys the specified polling group and frees associated resources.
 * All leftover sockets associated with this group are destroyed implicitly.
 *
 * @param group The polling group to destroy
 * @return 0 on success, -1 on error
 */
int xlio_poll_group_destroy(xlio_poll_group_t group);

/**
 * @brief Update polling group attributes
 *
 * Updates the attributes of an existing polling group. This allows changing
 * callback functions or flags without recreating the group.
 *
 * @param group The polling group to update
 * @param attr New attributes for the group
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid parameters (attr is NULL or socket_event_cb is NULL)
 */
int xlio_poll_group_update(xlio_poll_group_t group, const struct xlio_poll_group_attr *attr);

/**
 * @brief Poll for events on a polling group
 *
 * This is the main event processing function. It polls hardware for events,
 * executes TCP timers, and invokes registered callbacks. Most network events
 * are processed from the context of this call.
 *
 * @param group The polling group to poll
 *
 * @note This function should be called regularly in the main event loop.
 * It's non-blocking and will return immediately if no events are available.
 */
void xlio_poll_group_poll(xlio_poll_group_t group);

/** @} */ // end of xlio_poll_group group

/**
 * @defgroup xlio_socket Socket Management
 * @brief Functions for creating and managing XLIO sockets
 *
 * XLIO sockets are high-performance TCP socket abstractions that provide
 * zero-copy capabilities. They are represented by opaque handles rather than
 * file descriptors.
 *
 * @{
 */

/**
 * @brief Create a new XLIO socket
 *
 * Creates a new XLIO socket with the specified attributes. The socket is
 * automatically associated with the specified polling group and configured
 * for high-performance operation.
 *
 * @param attr Socket attributes
 * @param sock_out Pointer to store the created socket handle
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid parameters (sock_out is NULL, attr is NULL, group is invalid,
 *           or domain is not AF_INET/AF_INET6)
 * - ENOMEM: Insufficient memory
 * - EMFILE: Too many open files
 *
 * @see xlio_socket_destroy()
 * @see xlio_socket_attr
 */
int xlio_socket_create(const struct xlio_socket_attr *attr, xlio_socket_t *sock_out);

/**
 * @brief Destroy an XLIO socket
 *
 * Initiates the socket closing procedure. The process may be asynchronous,
 * and socket events may continue to arrive until the XLIO_SOCKET_EVENT_TERMINATED
 * event is received.
 *
 * @param sock The socket to destroy
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - EINVAL: Invalid socket handle
 *
 * @note Zero-copy completion events may still arrive after calling this function
 * until the TERMINATED event is received.
 */
int xlio_socket_destroy(xlio_socket_t sock);

/**
 * @brief Update socket attributes
 *
 * Updates the flags and user data associated with a socket. This allows
 * changing socket behavior and context without recreating the socket.
 *
 * @param sock The socket to update
 * @param flags New flags for the socket
 * @param userdata_sq New user data for the socket
 * @return 0 on success, -1 on error
 */
int xlio_socket_update(xlio_socket_t sock, unsigned flags, uintptr_t userdata_sq);

/**
 * @brief Set socket options
 *
 * Sets socket options, similar to the standard setsockopt() function.
 * Supports standard socket options as well as XLIO-specific options.
 *
 * @param sock The socket to configure
 * @param level The protocol level (SOL_SOCKET, IPPROTO_TCP, etc.)
 * @param optname The option name
 * @param optval Pointer to the option value
 * @param optlen Length of the option value
 * @return 0 on success, -1 on error (errno is set)
 *
 * @see setsockopt(2)
 */
int xlio_socket_setsockopt(xlio_socket_t sock, int level, int optname, const void *optval,
                           socklen_t optlen);

/**
 * @brief Get socket name
 *
 * Retrieves the local address of the socket, similar to getsockname().
 *
 * @param sock The socket to query
 * @param addr Buffer to store the address
 * @param addrlen Pointer to the address length
 * @return 0 on success, -1 on error (errno is set)
 *
 * @see getsockname(2)
 */
int xlio_socket_getsockname(xlio_socket_t sock, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief Get peer name
 *
 * Retrieves the remote address of the socket, similar to getpeername().
 *
 * @param sock The socket to query
 * @param addr Buffer to store the address
 * @param addrlen Pointer to the address length
 * @return 0 on success, -1 on error (errno is set)
 *
 * @see getpeername(2)
 */
int xlio_socket_getpeername(xlio_socket_t sock, struct sockaddr *addr, socklen_t *addrlen);

/**
 * @brief Bind socket to address
 *
 * Binds the socket to a local address, similar to bind().
 *
 * @param sock The socket to bind
 * @param addr The address to bind to
 * @param addrlen Length of the address
 * @return 0 on success, -1 on error (errno is set)
 *
 * @see bind(2)
 */
int xlio_socket_bind(xlio_socket_t sock, const struct sockaddr *addr, socklen_t addrlen);

/**
 * @brief Connect socket to remote address
 *
 * Initiates a connection to a remote address. The operation is non-blocking,
 * and the connection status is reported via the socket event callback.
 *
 * @param sock The socket to connect
 * @param to The remote address to connect to
 * @param tolen Length of the remote address
 * @return 0 on success, -1 on error (errno is set)
 *
 * @note This function returns immediately. Connection establishment is
 * indicated by the XLIO_SOCKET_EVENT_ESTABLISHED event.
 *
 * @see connect(2)
 */
int xlio_socket_connect(xlio_socket_t sock, const struct sockaddr *to, socklen_t tolen);

/**
 * @brief Listen for incoming connections
 *
 * Configures the socket to listen for incoming connections. Requires that
 * the polling group has a socket_accept_cb callback registered.
 *
 * @param sock The socket to configure for listening
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - ENOTCONN: No accept callback registered in the polling group
 * - EINVAL: Socket is already connected
 * - EADDRINUSE: Another socket is already listening on the same port
 * - ENODEV: Trying to listen on a non-NVIDIA NIC or an internal error
 *           preventing the socket from being offloaded
 *
 * @note The socket must be bound before calling this function.
 *
 * @see listen(2)
 */
int xlio_socket_listen(xlio_socket_t sock);

/**
 * @brief Get InfiniBand protection domain
 *
 * Returns the InfiniBand protection domain associated with the socket.
 * This can be used for registering memory regions for zero-copy operations.
 *
 * @param sock The socket to query
 * @return Pointer to ibv_pd structure, or NULL on error
 *
 * @note Socket must be connected or in progress of connecting.
 */
struct ibv_pd *xlio_socket_get_pd(xlio_socket_t sock);

/**
 * @brief Detach socket from polling group
 *
 * Removes the socket from its current polling group. The socket becomes
 * inactive and will not generate events until attached to another group.
 *
 * @param sock The socket to detach
 * @return 0 on success, -1 on error
 *
 * @par Error Codes:
 * - EINVAL: Socket is not connected or already detached
 * - ENOTSUP: Not supported with listen sockets
 *
 * @note During the 2-step socket migration (detach -> attach), there is a time window
 * during which RX packets are dropped until the socket is completely attached to
 * the new group. Applications should minimize this window to avoid packet loss and
 * TCP retransmissions.
 */
int xlio_socket_detach_group(xlio_socket_t sock);

/**
 * @brief Attach socket to polling group
 *
 * Attaches a previously detached socket to a polling group. The socket
 * will begin generating events according to the group's configuration.
 *
 * @param sock The socket to attach
 * @param group The polling group to attach to
 * @return 0 on success, -1 on error
 *
 * @par Error Codes:
 * - EINVAL: Socket is already attached
 * - ENOMEM: No memory to complete the operation
 * - ENOTCONN: Failed to attach TX flow
 * - ECONNABORTED: Failed to attach RX flow
 */
int xlio_socket_attach_group(xlio_socket_t sock, xlio_poll_group_t group);

/** @} */ // end of xlio_socket group

/**
 * @defgroup xlio_tx Transmit Operations
 * @brief High-performance data transmission functions
 *
 * The XLIO Socket API provides efficient transmission capabilities with
 * zero-copy support and flexible batching options.
 *
 * @section tx_properties TX Flow Properties
 * - Non-blocking operation
 * - No partial write support - accepts all data unless memory allocation fails
 * - Zero-copy completion callbacks for memory management
 * - Inline send operations support for small data
 * - Data aggregation with explicit flush control
 *
 * @section tx_limitations TX Flow Limitations
 * - Currently, data can be pushed to wire in the RX flow regardless of the flush logic
 * - Avoid using xlio_socket_flush() for a XLIO_GROUP_FLAG_DIRTY group
 * - For a XLIO_GROUP_FLAG_DIRTY group, usage of XLIO_SOCKET_SEND_FLAG_FLUSH is limited,
 *   it's better to avoid using them both simultaneously.
 *
 * @{
 */

/**
 * @brief Send data on a socket
 *
 * Sends data on the specified socket using zero-copy by default.
 * The operation is non-blocking and accepts all data unless memory allocation fails.
 *
 * @param sock The socket to send data on
 * @param data Pointer to the data to send
 * @param len Length of the data
 * @param attr Send attributes controlling the operation
 * @return 0 on success, -1 on error (errno is set)
 *
 * @par Error Codes:
 * - ENOMEM: Insufficient memory (recoverable by retrying later)
 * - Other errors are generally not recoverable
 *
 * @note For zero-copy operation, the memory must be registered with the
 * InfiniBand protection domain obtained from xlio_socket_get_pd().
 *
 * @see xlio_socket_send_attr
 */
int xlio_socket_send(xlio_socket_t sock, const void *data, size_t len,
                     const struct xlio_socket_send_attr *attr);

/**
 * @brief Send vectored data on a socket
 *
 * Sends data from multiple buffers (scatter-gather) on the specified socket.
 *
 * @param sock The socket to send data on
 * @param iov Array of iovec structures describing the data buffers
 * @param iovcnt Number of iovec structures
 * @param attr Send attributes controlling the operation
 * @return 0 on success, -1 on error (errno is set)
 *
 * @see xlio_socket_send()
 */
int xlio_socket_sendv(xlio_socket_t sock, const struct iovec *iov, unsigned iovcnt,
                      const struct xlio_socket_send_attr *attr);

/**
 * @brief Flush all dirty sockets in a polling group
 *
 * For polling groups created with XLIO_GROUP_FLAG_DIRTY, this function
 * flushes all sockets that have pending data to send. This provides
 * batch flushing capabilities for improved performance.
 *
 * @param group The polling group to flush
 *
 * @note This function should only be used with groups that have the
 * XLIO_GROUP_FLAG_DIRTY flag set.
 */
void xlio_poll_group_flush(xlio_poll_group_t group);

/**
 * @brief Flush pending data on a socket
 *
 * Forces transmission of any data queued on the socket. XLIO aggregates data
 * by default for efficiency and user logic simplification.
 *
 * This function doesn't guarantee immediate transmission, because TCP algorithms
 * and congestion/flow control may affect transmission.
 *
 * @param sock The socket to flush
 *
 * @note Avoid using this function with sockets in XLIO_GROUP_FLAG_DIRTY groups.
 * Use xlio_poll_group_flush() instead for better performance for such groups.
 */
void xlio_socket_flush(xlio_socket_t sock);

/** @} */ // end of xlio_tx group

/**
 * @defgroup xlio_rx Receive Operations
 * @brief Zero-copy receive buffer management
 *
 * The XLIO Socket API provides zero-copy receive capabilities through
 * a buffer management system. Received data is delivered via callbacks
 * with buffer descriptors that must be returned to the system.
 *
 * xlio_buf structure contains an uninitialized userdata field which can be used
 * by the application to store any data during its ownership on the buffer.
 * For example, the field can be used to organize a list without a container
 * allocation, or to add a reference counter to the buffer.
 *
 * @section rx_data_alignment Data Alignment Considerations
 * XLIO Ultra API does not guarantee alignment for zero-copy RX data. The data
 * alignment depends on the underlying network headers and packet structure.
 *
 * @{
 */

/**
 * @brief Free a receive buffer (socket-specific)
 *
 * Returns a receive buffer to the system for reuse. This function should
 * be called for every buffer received via the RX callback.
 *
 * @param sock The socket that received the buffer
 * @param buf The buffer descriptor to free
 *
 * @note The buffer must not be accessed after calling this function.
 */
void xlio_socket_buf_free(xlio_socket_t sock, struct xlio_buf *buf);

/**
 * @brief Free a receive buffer (group-specific)
 *
 * Returns a receive buffer to the system for reuse. This function allows to
 * return a buffer outside of the original socket lifecycle.
 *
 * @param group The polling group
 * @param buf The buffer descriptor to free
 *
 * @note The buffer must not be accessed after calling this function.
 */
void xlio_poll_group_buf_free(xlio_poll_group_t group, struct xlio_buf *buf);

/** @} */ // end of xlio_rx group

/** @} */ // end of xlio_socket_api group

#ifdef __cplusplus
}
#endif
#endif /* XLIO_H */
