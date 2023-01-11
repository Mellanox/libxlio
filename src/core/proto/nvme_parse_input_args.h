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

#ifndef XLIO_NVME_PARSE_INPUT_ARGS_H
#define XLIO_NVME_PARSE_INPUT_ARGS_H

static inline bool is_valid_aux_data_array(const xlio_pd_key *aux, size_t aux_data_sz)
{
    return aux != nullptr && aux_data_sz > 0;
}

static inline bool is_new_nvme_pdu(const xlio_pd_key *aux, size_t aux_data_sz)
{
    return is_valid_aux_data_array(aux, aux_data_sz) && aux->message_length > 0 && aux->mkey != 0U;
}

struct NVMEoTCP_TX {

    NVMEoTCP_TX() = default;
    operator bool() const { return m_iov_num != 0U; }

    static NVMEoTCP_TX *from_batch(const iovec *iov, const xlio_pd_key *aux_data, size_t num)
    {
        return new NVMEoTCP_TX(iov, aux_data, num);
    }

    struct iovec_view;
    const iovec_view get_next_iovec_view()
    {
        if (!*this) {
            return iovec_view();
        }
        /* The iovec batches may contain multiple NVME PDUs. Each PDU may span multiple complete
         * iovec segments. */
        size_t remaining_pdu_length = m_aux_data[m_current_view_index].message_length;
        size_t current_index = m_current_view_index;

        while (remaining_pdu_length != 0U && remaining_pdu_length >= m_iov[current_index].iov_len) {
            remaining_pdu_length -= m_iov[current_index].iov_len;
            current_index++;
        }

        if (current_index <= m_iov_num && remaining_pdu_length == 0) {
            iovec_view view {&m_iov[m_current_view_index], &m_aux_data[m_current_view_index],
                             current_index - m_current_view_index};
            m_current_view_index = current_index;
            return view;
        }
        return iovec_view();
    }

    struct iovec_view {
        iovec_view(const iovec *iov, const xlio_pd_key *aux_data, size_t num)
            : m_iov(iov)
            , m_aux_data(aux_data)
            , m_iov_num(num) {};

        iovec_view() = default;
        operator bool() const
        {
            return m_iov != nullptr && m_aux_data != nullptr && m_iov_num != 0U;
        }
        const iovec *m_iov;
        const xlio_pd_key *m_aux_data;
        size_t m_iov_num;
    };

private:
    NVMEoTCP_TX(const iovec *iov, const xlio_pd_key *aux_data, size_t iov_num)
        : m_iov_num(iov_num)
        , m_current_view_index(0)
    {
        if (iov != nullptr && aux_data != nullptr && iov_num <= 64U) {
            memcpy(&m_iov[0], iov, m_iov_num * sizeof(*iov));
            memcpy(&m_aux_data[0], aux_data, m_iov_num * sizeof(iovec));
        } else {
            m_iov_num = 0;
        }
    };

    iovec m_iov[64U];
    /* The aux_data member contains an array of structures with message_length and mkey fields.
     * message_length indicates the start of the PDU while mkey the memory key of the
     * pre-registered memory regions. A zero mkey indicates non-registered memory.
     */
    xlio_pd_key m_aux_data[64U];
    size_t m_iov_num;
    size_t m_current_view_index;
};

#endif /* XLIO_NVME_PARSE_INPUT_ARGS_H */
