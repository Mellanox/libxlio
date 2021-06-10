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


#ifndef QP_MGR_ETH_MLX5_H
#define QP_MGR_ETH_MLX5_H

#include "qp_mgr.h"
#include "vma/util/sg_array.h"
#include "vma/dev/dm_mgr.h"

#ifdef DEFINED_UTLS
#include <linux/tls.h>
#endif /* DEFINED_UTLS */

#if defined(DEFINED_DIRECT_VERBS)

class qp_mgr_eth_mlx5 : public qp_mgr_eth
{
friend class cq_mgr_mlx5;
public:
	qp_mgr_eth_mlx5(struct qp_mgr_desc *desc,
			const uint32_t tx_num_wr,
			const uint16_t vlan, bool call_configure = true);
	virtual ~qp_mgr_eth_mlx5();
	virtual void	up();
	virtual void	down();
	virtual void    post_recv_buffer(mem_buf_desc_t* p_mem_buf_desc); // Post for receive single mem_buf_desc
	vma_ib_mlx5_qp_t    m_mlx5_qp;

#ifdef DEFINED_UTLS
	void tls_context_setup(
		const void *info, uint32_t tis_number,
		uint32_t dek_id, uint32_t initial_tcp_sn);
	void tls_tx_post_dump_wqe(uint32_t tis_number, void *addr, uint32_t len, uint32_t lkey);
#endif /* DEFINED_UTLS */
	void post_nop_fence(void);

protected:
	void		trigger_completion_for_all_sent_packets();
	void		init_sq();

	uint64_t*   m_sq_wqe_idx_to_wrid;
	uint64_t    m_rq_wqe_counter;
private:
	cq_mgr*		init_rx_cq_mgr(struct ibv_comp_channel* p_rx_comp_event_channel);
	virtual cq_mgr*	init_tx_cq_mgr(void);
	virtual bool	is_completion_need() { return !m_n_unsignaled_count || (m_dm_enabled && m_dm_mgr.is_completion_need()); };
	virtual void	dm_release_data(mem_buf_desc_t* buff) { m_dm_mgr.release_data(buff); }

	inline void	set_signal_in_next_send_wqe();
	int		send_to_wire(vma_ibv_send_wr* p_send_wqe, vma_wr_tx_packet_attr attr, bool request_comp, uint32_t tisn);
	inline int	fill_wqe(vma_ibv_send_wr* p_send_wqe);
#ifdef DEFINED_UTLS
	inline void tls_tx_fill_static_params_wqe(
		struct mlx5_wqe_tls_static_params_seg* params,
		const struct tls12_crypto_info_aes_gcm_128* info,
		uint32_t key_id, uint32_t resync_tcp_sn);
	inline void tls_tx_post_static_params_wqe(
		const struct tls12_crypto_info_aes_gcm_128* info,
		uint32_t tis_number, uint32_t key_id, uint32_t resync_tcp_sn);
	inline void tls_tx_fill_progress_params_wqe(
		struct mlx5_wqe_tls_progress_params_seg* params,
		uint32_t tis_number, uint32_t next_record_tcp_sn);
	inline void tls_tx_post_progress_params_wqe(
		uint32_t tis_number, uint32_t next_record_tcp_sn);
#endif /* DEFINED_UTLS */
#ifdef DEFINED_TSO
	inline int	fill_wqe_send(vma_ibv_send_wr* pswr);
	inline int	fill_wqe_lso(vma_ibv_send_wr* pswr);
	inline void	ring_doorbell(uint64_t* wqe, int db_method, int num_wqebb, int num_wqebb_top = 0);
#else
	inline void	ring_doorbell(uint64_t* wqe, int num_wqebb, int num_wqebb_top = 0);
#endif /* DEFINED_TSO */
	inline int	fill_inl_segment(sg_array &sga, uint8_t *cur_seg, uint8_t* data_addr, int max_inline_len, int inline_len);
	inline int	fill_ptr_segment(sg_array &sga, struct mlx5_wqe_data_seg* dp_seg, uint8_t* data_addr, int data_len, mem_buf_desc_t* buffer);

	struct mlx5_eth_wqe	(*m_sq_wqes)[];
	struct mlx5_eth_wqe*	m_sq_wqe_hot;
	uint8_t*		m_sq_wqes_end;
	enum {
		MLX5_DB_METHOD_BF,
		MLX5_DB_METHOD_DB
	} m_db_method;

	int                 m_sq_wqe_hot_index;
	uint16_t            m_sq_wqe_counter;
	dm_mgr              m_dm_mgr;
	bool                m_dm_enabled;
};
#endif //defined(DEFINED_DIRECT_VERBS)
#endif //QP_MGR_ETH_MLX5_H
