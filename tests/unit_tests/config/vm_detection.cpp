/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "core/util/vm_detection.h"
#include <gtest/gtest.h>
#include <sstream>

namespace {
class arm_firmware : public testing::Test {
protected:
    std::istringstream hypervisor, machine, vendor, product;

    vm_detection::hyper_t detect()
    {
        return vm_detection::classify_arm_firmware(hypervisor, machine, vendor, product);
    }
};

TEST_F(arm_firmware, reads_all_device_tree_entries)
{
    const char ids[] = "vendor,board\0qemu,virt\0xen,xenvm-4.17\0";
    machine.str(std::string(ids, sizeof(ids) - 1));
    EXPECT_EQ(vm_detection::HYPER_XEN, detect());
}

TEST_F(arm_firmware, specific_smbios_match_overrides_generic_device_tree)
{
    machine.str("linux,dummy-virt");
    product.str("Arm kVm guest\n");
    EXPECT_EQ(vm_detection::HYPER_KVM, detect());
}

TEST_F(arm_firmware, recognizes_hyperv_from_both_smbios_fields)
{
    vendor.str("Microsoft Corporation\n");
    product.str("Virtual Machine\n");
    EXPECT_EQ(vm_detection::HYPER_MSHV, detect());
}

TEST_F(arm_firmware, generic_product_alone)
{
    product.str("Virtual Machine\n");
    EXPECT_EQ(vm_detection::HYPER_OTHER, detect());
}

TEST_F(arm_firmware, bare_metal_identifiers)
{
    machine.str("nvidia,bluefield");
    vendor.str("Microsoft Corporation\n");
    product.str("Surface\n");
    EXPECT_EQ(vm_detection::HYPER_NONE, detect());
}

TEST_F(arm_firmware, missing_firmware_files)
{
    for (auto *input : {&hypervisor, &machine, &vendor, &product}) {
        input->setstate(std::ios::failbit);
    }
    EXPECT_EQ(vm_detection::HYPER_NONE, detect());
}

TEST_F(arm_firmware, missing_device_tree_with_vmware_smbios)
{
    hypervisor.setstate(std::ios::failbit);
    machine.setstate(std::ios::failbit);
    vendor.str("VMware, Inc.\n");
    EXPECT_EQ(vm_detection::HYPER_VMWARE, detect());
}

TEST_F(arm_firmware, explicit_hyperv_signature)
{
    hypervisor.str("microsoft,hyperv");
    EXPECT_EQ(vm_detection::HYPER_MSHV, detect());
}

TEST_F(arm_firmware, generic_qemu_platform)
{
    machine.str("linux,dummy-virt");
    EXPECT_EQ(vm_detection::HYPER_OTHER, detect());
}
TEST(x86_hypervisor, cpuid_vendor_signatures)
{
    EXPECT_EQ(vm_detection::HYPER_XEN, vm_detection::classify_x86_vendor("XenVMMXenVMM"));
    EXPECT_EQ(vm_detection::HYPER_KVM, vm_detection::classify_x86_vendor("KVMKVMKVM"));
    EXPECT_EQ(vm_detection::HYPER_VMWARE, vm_detection::classify_x86_vendor("VMwareVMware"));
    EXPECT_EQ(vm_detection::HYPER_MSHV, vm_detection::classify_x86_vendor("Microsoft Hv"));
    EXPECT_EQ(vm_detection::HYPER_NONE, vm_detection::classify_x86_vendor("Unknown"));
}
} // namespace
