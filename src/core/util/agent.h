/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _AGENT_H_
#define _AGENT_H_

#include "core/util/agent_def.h"

/**
 * @struct agent_msg_t
 * @brief Agent message resource descriptor.
 *
 * This structure describes a internal message object.
 */
typedef struct agent_msg {
    struct list_head item; /**< link element */
    int length; /**< actual length of valuable data */
    intptr_t tag; /**< unique identifier of the message */
    union {
        struct xlio_msg_state state;
        char raw[1];
    } data; /**< data to be sent to daemon */
} agent_msg_t;

#define AGENT_MSG_TAG_INVALID (-1)

/**
 * @enum agent_state_t
 * @brief List of possible Agent states.
 */
typedef enum { AGENT_INACTIVE, AGENT_ACTIVE, AGENT_CLOSED } agent_state_t;

typedef void (*agent_cb_t)(void *arg);

/**
 * @struct agent_callback_t
 * @brief Callback queue element.
 *
 * This structure describes function call that is
 * done in case Agent change the state
 */
typedef struct agent_callback {
    struct list_head item; /**< link element */
    agent_cb_t cb; /**< Callback function */
    void *arg; /**< Function argument */
} agent_callback_t;

class agent {
public:
    agent();
    virtual ~agent();

    inline agent_state_t state(void) const { return m_state; }

    void register_cb(agent_cb_t fn, void *arg);
    void unregister_cb(agent_cb_t fn, void *arg);
    int put(const void *data, size_t length, intptr_t tag);
    void progress(void);

private:
    /* state of this object */
    agent_state_t m_state;

    /* socket used for communication with daemon */
    int m_sock_fd;

    /* file descriptor that is tracked by daemon */
    int m_pid_fd;

    /* unix socket name
     * size should be less than sockaddr_un.sun_path
     */
    char m_sock_file[100];

    /* name of pid file */
    char m_pid_file[100];

    /* queue of callback elements
     * this queue stores function calls activated during
     * state change
     */
    struct list_head m_cb_queue;

    /* thread-safe lock to protect operations
     * under the callback queue
     */
    lock_spin m_cb_lock;

    /* queue of message elements
     * this queue stores unused messages
     */
    struct list_head m_free_queue;

    /* queue of message elements
     * this queue stores messages from different sockets
     */
    struct list_head m_wait_queue;

    /* thread-safe lock to protect operations
     * under the message wait and free queues
     */
    lock_spin m_msg_lock;

    /* total number of allocated messages
     * some amount of messages are allocated during initialization
     * but total number can grow during run-time
     */
    int m_msg_num;

    int create_agent_socket(void);
    int send(agent_msg_t *msg);
    int send_msg_init(void);
    int send_msg_exit(void);
    void progress_cb(void);
    void check_link(void);
};

extern agent *g_p_agent;

#endif /* _AGENT_H_ */
