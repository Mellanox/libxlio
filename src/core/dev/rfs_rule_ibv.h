/*
 * Copyright (c) 2001-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef RFS_RULE_IBV_H
#define RFS_RULE_IBV_H

#include <memory>
#include "util/utils.h"
#include "ib/base/verbs_extra.h"
#include "dev/rfs_rule.h"

using namespace std;

template <typename T> using deleter_func = void (*)(T *);

template <typename T> using unique_ptr_delfunc = std::unique_ptr<T, deleter_func<T>>;

class rfs_rule_ibv : public rfs_rule {
public:
    virtual ~rfs_rule_ibv();

    bool create(xlio_ibv_flow_attr &attrs, ibv_qp *qp);

private:
    static void destory_ibv_flow(xlio_ibv_flow *flow);

    unique_ptr_delfunc<xlio_ibv_flow> _ibv_flow {nullptr, destory_ibv_flow};
};

#endif
