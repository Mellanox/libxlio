/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include "vm_detection.h"

#if defined(__x86_64__)
#include <cpuid.h>
#endif
#include <fstream>
#include <string.h>

namespace vm_detection {
hyper_t classify_arm_firmware(std::istream &hypervisor_compatible, std::istream &machine_compatible,
                              std::istream &sys_vendor, std::istream &product_name)
{
    auto result = HYPER_NONE;
    bool microsoft_vendor = false;
    bool virtual_machine_product = false;
    // Device-tree properties contain NUL-separated compatible strings. SMBIOS
    // attributes are single strings, so the same loop reads the whole value.
    for (auto *firmware :
         {&hypervisor_compatible, &machine_compatible, &sys_vendor, &product_name}) {
        std::string value;
        while (std::getline(*firmware, value, '\0')) {
            const char *id = value.c_str();
            if (strcasestr(id, "xen")) {
                return HYPER_XEN;
            }
            if (strcasestr(id, "kvm")) {
                return HYPER_KVM;
            }
            if (strcasestr(id, "vmware")) {
                return HYPER_VMWARE;
            }
            // An explicit Hyper-V signature identifies the guest immediately.
            // Otherwise, infer Hyper-V only when SMBIOS reports both the vendor
            // "Microsoft Corporation" and the product "Virtual Machine".
            if (strcasestr(id, "hyper-v") || strcasestr(id, "microsoft hv") ||
                strcasestr(id, "microsoft,hyperv")) {
                return HYPER_MSHV;
            }

            if (firmware == &sys_vendor) {
                microsoft_vendor = strcasestr(id, "Microsoft Corporation") != nullptr;
            }
            if (firmware == &product_name) {
                virtual_machine_product = strcasestr(id, "Virtual Machine") != nullptr;
            }

            // QEMU and generic virtual platforms do not identify the hypervisor.
            // Keep looking: SMBIOS may identify KVM on a QEMU virtual board.
            if (strcasestr(id, "qemu") || strcasestr(id, "linux,dummy-virt") ||
                virtual_machine_product) {
                result = HYPER_OTHER;
            }
        }
    }
    return microsoft_vendor && virtual_machine_product ? HYPER_MSHV : result;
}

hyper_t classify_x86_vendor(const char *vendor)
{
    if (!strncmp(vendor, "XenVMMXenVMM", 12)) {
        return HYPER_XEN;
    }
    if (!strncmp(vendor, "KVMKVMKVM", 9)) {
        return HYPER_KVM;
    }
    if (!strncmp(vendor, "Microsoft Hv", 12)) {
        return HYPER_MSHV;
    }
    if (!strncmp(vendor, "VMwareVMware", 12)) {
        return HYPER_VMWARE;
    }
    return HYPER_NONE;
}

hyper_t detect()
{
#if defined(__aarch64__)
    std::ifstream hypervisor("/proc/device-tree/hypervisor/compatible");
    std::ifstream machine("/proc/device-tree/compatible");
    std::ifstream vendor("/sys/class/dmi/id/sys_vendor");
    std::ifstream product("/sys/class/dmi/id/product_name");
    return classify_arm_firmware(hypervisor, machine, vendor, product);
#elif defined(__x86_64__)
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (ecx & (1U << 31)) {
        // The hypervisor leaf returns the 12-byte vendor ID in EBX, ECX, EDX order.
        __cpuid(0x40000000U, eax, ebx, ecx, edx);
        char vendor[13] = {};
        memcpy(vendor, &ebx, 4);
        memcpy(vendor + 4, &ecx, 4);
        memcpy(vendor + 8, &edx, 4);
        return classify_x86_vendor(vendor);
    }
#endif
    return HYPER_NONE;
}
} // namespace vm_detection
