/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#include <vector>

#include "utils/bullseye.h"
#include "vlogger/vlogger.h"
#include "ib_ctx_handler_collection.h"

#include "ib/base/verbs_extra.h"
#include "util/utils.h"
#include "event/event_handler_manager.h"

#define MODULE_NAME "ib_ctx_collection"
DOCA_LOG_REGISTER(ib_ctx_collection);

#define ibchc_logpanic   __log_panic
#define ibchc_logerr     __log_err
#define ibchc_logwarn    __log_warn
#define ibchc_loginfo    __log_info
#define ibchc_logdbg     __log_info_dbg
#define ibchc_logfunc    __log_info_func
#define ibchc_logfuncall __log_info_funcall

ib_ctx_handler_collection *g_p_ib_ctx_handler_collection = nullptr;

ib_ctx_handler_collection::ib_ctx_handler_collection()
{
    ibchc_logdbg(LOG_FUNCTION_CALL);

    /* Read ib table from kernel and save it in local variable. */
    update_tbl();

    // Print table
    print_val_tbl();

    ibchc_logdbg("Done");
}

ib_ctx_handler_collection::~ib_ctx_handler_collection()
{
    ibchc_logdbg(LOG_FUNCTION_CALL);

    ib_context_map_t::iterator ib_ctx_iter;
    while ((ib_ctx_iter = m_ib_ctx_map.begin()) != m_ib_ctx_map.end()) {
        ib_ctx_handler *p_ib_ctx_handler = *ib_ctx_iter;
        delete p_ib_ctx_handler;
        m_ib_ctx_map.erase(ib_ctx_iter);
    }

    ibchc_logdbg("Done");
}

#ifndef DEFINED_DPCP_PATH_RX
void ib_ctx_handler_collection::stop_all_doca_flow_ports()
{
    ibchc_logdbg(LOG_FUNCTION_CALL);
    for (auto itr : m_ib_ctx_map) {
        itr->get_ctx_doca_dev().stop_doca_flow_port();
    }
}
#endif // !DEFINED_DPCP_PATH_RX

void ib_ctx_handler_collection::update_tbl()
{
    ibchc_logdbg("Checking for offload capable IB devices...");
    uint32_t num_devices_doca = 0U;
    int num_devices_ibv = 0;

#ifndef DEFINED_DPCP_PATH_ONLY
    doca_devinfo **dev_list_doca;
    doca_error_t err = doca_devinfo_create_list(&dev_list_doca, &num_devices_doca);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibchc_logerr, err, "doca_devinfo_create_list");
        return;
    }

    char doca_ifname_name[DOCA_DEVINFO_IFACE_NAME_SIZE] = {0};
    char doca_ibdev_name[DOCA_DEVINFO_IFACE_NAME_SIZE] = {0};
#endif // !DEFINED_DPCP_PATH_ONLY

#ifdef DEFINED_DPCP_PATH_ANY
    struct ibv_device **dev_list = xlio_ibv_get_device_list(&num_devices_ibv);

    BULLSEYE_EXCLUDE_BLOCK_START
    if (!dev_list || num_devices_ibv <= 0) {
        ibchc_logerr(
            "Failure in xlio_ibv_get_device_list() (error=%d %m). Please check rdma configuration",
            errno);
        throw_xlio_exception("No IB capable devices found!");
    }

    BULLSEYE_EXCLUDE_BLOCK_END
#endif // DEFINED_DPCP_PATH_ANY

    uint32_t devices_num =
        (num_devices_doca > 0U ? num_devices_doca : static_cast<uint32_t>(num_devices_ibv));
    for (uint32_t devidx = 0; devidx < devices_num; devidx++) {
#ifndef DEFINED_DPCP_PATH_ONLY
        doca_error_t err_iface = doca_devinfo_get_iface_name(
            dev_list_doca[devidx], doca_ifname_name, sizeof(doca_ifname_name));
        doca_error_t err_ibdev = doca_devinfo_get_ibdev_name(dev_list_doca[devidx], doca_ibdev_name,
                                                             sizeof(doca_ibdev_name));
        if (DOCA_IS_ERROR(err_iface) || DOCA_IS_ERROR(err_ibdev)) {
            ibchc_logwarn("DOCA warning: doca_devinfo_get_iface_name returns %d!", err_iface);
            ibchc_logwarn("DOCA warning: doca_devinfo_get_ibdev_name returns %d!", err_ibdev);
            continue;
        }

        ibchc_logdbg("DOCA dev found: ifname: %s -> ibname: %s", doca_ifname_name, doca_ibdev_name);
#ifdef DEFINED_DPCP_PATH_ANY
        int ibidx = 0;
        for (; ibidx < num_devices_ibv; ++ibidx) {
            if (0 ==
                strncmp(dev_list[ibidx]->name, doca_ibdev_name, DOCA_DEVINFO_IFACE_NAME_SIZE)) {
                break;
            }
        }

        if (ibidx == num_devices_ibv) {
            ibchc_logerr("IBV device not found for DOCA dev %s", doca_ibdev_name);
            continue;
        }

        ib_ctx_handler *p_ib_ctx_handler = new ib_ctx_handler(doca_ibdev_name);
        p_ib_ctx_handler->construct_ctx_ibv_dev(dev_list[ibidx]);
        p_ib_ctx_handler->construct_ctx_doca_dev(dev_list_doca[devidx], doca_ifname_name);
        ibchc_logdbg("DOCA dev initialized: %s,%s -> IBV: %s", doca_ifname_name, doca_ibdev_name,
                     dev_list[ibidx]->name);
#else // DEFINED_DPCP_PATH_ANY
        ib_ctx_handler *p_ib_ctx_handler = new ib_ctx_handler(doca_ibdev_name);
        p_ib_ctx_handler->construct_ctx_doca_dev(dev_list_doca[devidx], doca_ifname_name);
        ibchc_logdbg("DOCA dev initialized: %s,%s", doca_ifname_name, doca_ibdev_name);
#endif // DEFINED_DPCP_PATH_ANY
#else // !DEFINED_DPCP_PATH_ONLY
        ib_ctx_handler *p_ib_ctx_handler = new ib_ctx_handler(dev_list[devidx]->name);
        p_ib_ctx_handler->construct_ctx_ibv_dev(dev_list[devidx]);
        ibchc_logdbg("IBV dev initialized: %s", dev_list[devidx]->name);
#endif // !DEFINED_DPCP_PATH_ONLY

        m_ib_ctx_map.emplace(p_ib_ctx_handler);
    }

    ibchc_logdbg("Check completed. Found %lu offload capable IB devices", m_ib_ctx_map.size());

#ifdef DEFINED_DPCP_PATH_ANY
    if (dev_list) {
        ibv_free_device_list(dev_list);
    }
#endif // DEFINED_DPCP_PATH_ANY

#ifndef DEFINED_DPCP_PATH_ONLY
    err = doca_devinfo_destroy_list(dev_list_doca);
    if (DOCA_IS_ERROR(err)) {
        PRINT_DOCA_ERR(ibchc_logerr, err, "doca_devinfo_destroy_list");
    }
#endif // !DEFINED_DPCP_PATH_ONLY
}

void ib_ctx_handler_collection::print_val_tbl()
{
    ib_context_map_t::iterator itr;
    for (itr = m_ib_ctx_map.begin(); itr != m_ib_ctx_map.end(); itr++) {
        (*itr)->print_val();
    }
}

ib_ctx_handler *ib_ctx_handler_collection::get_ib_ctx(const char *ifa_name)
{
    char active_slave[IFNAMSIZ] = {0};
    ib_context_map_t::iterator ib_ctx_iter;

    if (check_bond_device_exist(ifa_name)) {
        /* active/backup: return active slave */
        if (!get_bond_active_slave_name(ifa_name, active_slave, sizeof(active_slave))) {
            char slaves[IFNAMSIZ * 16] = {0};
            char *slave_name;
            char *save_ptr;

            /* active/active: return the first slave */
            if (!get_bond_slaves_name_list(ifa_name, slaves, sizeof(slaves))) {
                return nullptr;
            }
            slave_name = strtok_r(slaves, " ", &save_ptr);
            if (!slave_name) {
                return nullptr;
            }
            save_ptr = strchr(slave_name, '\n');
            if (save_ptr) {
                *save_ptr = '\0'; // Remove the tailing 'new line" char
            }
            strncpy(active_slave, slave_name, sizeof(active_slave) - 1);
        }
    }

    for (ib_ctx_iter = m_ib_ctx_map.begin(); ib_ctx_iter != m_ib_ctx_map.end(); ib_ctx_iter++) {
#ifndef DEFINED_DPCP_PATH_ONLY
        if ((*ib_ctx_iter)->get_ctx_doca_dev().get_ifname() == ifa_name) {
            return *ib_ctx_iter;
        }
#else // DEFINED_DPCP_PATH_ONLY
        if (check_device_name_ib_name(ifa_name, (*ib_ctx_iter)->get_ibname().c_str())) {
            return *ib_ctx_iter;
        }
#endif // !DEFINED_DPCP_PATH_ONLY
    }

    return nullptr;
}
