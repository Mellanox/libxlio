/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <iosfwd>

namespace vm_detection {
enum hyper_t { HYPER_NONE = 0, HYPER_XEN, HYPER_KVM, HYPER_MSHV, HYPER_VMWARE, HYPER_OTHER };

hyper_t classify_arm_firmware(std::istream &hypervisor_compatible, std::istream &machine_compatible,
                              std::istream &sys_vendor, std::istream &product_name);
hyper_t classify_x86_vendor(const char *vendor);
hyper_t detect();
} // namespace vm_detection
