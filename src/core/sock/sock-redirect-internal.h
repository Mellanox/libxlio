/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#ifndef SOCK_REDIRECT_INTERNAL_H
#define SOCK_REDIRECT_INTERNAL_H

#include "config.h"

/*
 * Workaround for clang compilation error with fortified wrapper redefinition.
 */
#ifdef __clang__
#ifdef HAVE___READ_CHK
#define read read_unused
#endif
#ifdef HAVE___RECV_CHK
#define recv recv_unused
#endif
#ifdef HAVE___RECVFROM_CHK
#define recvfrom recvfrom_unused
#endif
#ifdef HAVE___POLL_CHK
#define poll poll_unused
#endif
#ifdef HAVE___PPOLL_CHK
#define ppoll ppoll_unused
#endif
#endif /* __clang__ */
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#ifdef __clang__
#ifdef HAVE___READ_CHK
#undef read
#endif
#ifdef HAVE___RECV_CHK
#undef recv
#endif
#ifdef HAVE___RECVFROM_CHK
#undef recvfrom
#endif
#ifdef HAVE___POLL_CHK
#undef poll
#endif
#ifdef HAVE___PPOLL_CHK
#undef ppoll
#endif
#endif /* __clang__ */

#endif /* SOCK_REDIRECT_INTERNAL_H */
