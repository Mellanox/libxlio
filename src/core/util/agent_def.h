/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef _AGENT_DEF_H_
#define _AGENT_DEF_H_

#ifndef offsetof
#define offsetof(type, member) ((uintptr_t) & ((type *)0)->member)
#endif

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) (type *)((char *)(ptr)-offsetof(type, member))
#endif

/* List of supported messages in range 0..63
 * Two bits as 6-7 are reserved.
 * 6-bit is reserved
 * 7-bit in message code is for ACK flag in case specific
 * message requires the confirmation
 */
#define XLIO_MSG_INIT  0x01
#define XLIO_MSG_STATE 0x02
#define XLIO_MSG_EXIT  0x03
#define XLIO_MSG_ACK   0x80

#define XLIO_AGENT_VER 0x04

#define XLIO_AGENT_BASE_NAME "xlioagent"
#define XLIO_AGENT_ADDR      "/var/run/" XLIO_AGENT_BASE_NAME ".sock"
#define XLIO_AGENT_PATH      "/tmp/xlio"

#pragma pack(push, 1)
struct xlio_hdr {
    uint8_t code; /* code of message */
    uint8_t ver; /* format version */
    uint8_t status; /* status (require answer or return code for reply message) */
    uint8_t reserve[1]; /* unused */
    int32_t pid; /* process id */
};

struct xlio_msg_init {
    struct xlio_hdr hdr;
    uint32_t ver;
};

struct xlio_msg_exit {
    struct xlio_hdr hdr;
};

struct xlio_msg_state {
    struct xlio_hdr hdr;
    uint32_t fid;
    struct {
        uint16_t family;
        uint16_t port;
        union {
            uint32_t ipv4;
            uint8_t ipv6[16];
        } addr;
    } src;
    struct {
        uint16_t family;
        uint16_t port;
        union {
            uint32_t ipv4;
            uint8_t ipv6[16];
        } addr;
    } dst;
    uint8_t type;
    uint8_t state;
};

#pragma pack(pop)

#endif /* _AGENT_DEF_H_ */
