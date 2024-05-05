/*
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
#ifndef _RING_TX_SCHEDULER_INTERFACE_H_
#define _RING_TX_SCHEDULER_INTERFACE_H_

#include <cstdint>
class tcp_segment;
class udp_datagram;
class control_msg;
class sockinfo_tx_scheduler_interface;

class ring_tx_scheduler_interface {
public:
    virtual ~ring_tx_scheduler_interface() = default;

    virtual void notify_complete(uintptr_t) = 0;
    virtual size_t send(tcp_segment &, uintptr_t) = 0;
    virtual size_t send(udp_datagram &, uintptr_t) = 0;
    virtual size_t send(control_msg &, uintptr_t) = 0;
    virtual void schedule_tx(sockinfo_tx_scheduler_interface *, bool) = 0;
};

#endif // _RING_TX_SCHEDULER_INTERFACE_H_