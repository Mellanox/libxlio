/*
 * Copyright (c) 2001-2021 Mellanox Technologies, Ltd. All rights reserved.
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

#include <cinttypes>
#include "vma/dev/rfs_rule_ibv.h"

#define MODULE_NAME "rfs_rule_ibv"

rfs_rule_ibv::~rfs_rule_ibv()
{
}

bool rfs_rule_ibv::create(vma_ibv_flow_attr& attrs, ibv_qp* qp)
{
    _ibv_flow.reset(vma_ibv_create_flow(qp, &attrs));
    if (_ibv_flow != nullptr) {
        rfs_logdbg("Succeeded vma_ibv_create_flow, Type: %u, Priority %" PRIu16 ", rfs_rule_ibv: %p, ibv_flow: %p", 
            static_cast<unsigned int>(attrs.type), attrs.priority, this, _ibv_flow.get());
        return true;
    }
    
    rfs_logerr("Failed vma_ibv_create_flow, Type: %u, Priority %" PRIu16, 
            static_cast<unsigned int>(attrs.type), attrs.priority);
    return false;
}

void rfs_rule_ibv::destory_ibv_flow(vma_ibv_flow* flow)
{
    IF_VERBS_FAILURE_EX(vma_ibv_destroy_flow(flow), EIO) {
        __log_err("Failed vma_ibv_destroy_flow, ibv_flow: %p", flow); 
    } else {
        __log_dbg("Success vma_ibv_destroy_flow, ibv_flow: %p", flow); 
    } ENDIF_VERBS_FAILURE;
}

