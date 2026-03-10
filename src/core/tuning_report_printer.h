/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <atomic>
#include <cstdint>

// Process-local tuning-report counters, incremented in socket destructors.
struct tuning_report_counters_t {
    std::atomic<uint64_t> socket_offloaded_destructor_counter {0};
    std::atomic<uint64_t> socket_non_offloaded_destructor_counter {0};
};

extern tuning_report_counters_t g_tuning_report_counters;

/**
 * Check if anomalies were detected during this process run.
 *
 * Scans buffer pool allocation failures, HW RX drop counters,
 * and other health indicators. Used by the exit path to decide
 * whether to generate the report in "auto" mode.
 *
 * @return true if any anomaly is detected, false if clean run
 */
bool tuning_report_has_errors();

/**
 * Generate a comprehensive tuning report at process exit.
 *
 * The report is a structured text file containing:
 * - System context (NIC, CPU, kernel, OFED, hugepages, command line)
 * - Active profile and execution mode
 * - Full effective config (non-defaults flagged with titles)
 * - Runtime stats summary (Phase 2)
 * - Performance indicators with anomaly annotations (Phase 2)
 *
 * Designed to be pasted into an LLM chatbot or shared with
 * engineers for configuration optimization.
 *
 * @param file_path Path to write the report file
 * @return 0 on success, -1 on failure
 */
int generate_tuning_report(const char *file_path);

/**
 * Exit-time hook for the tuning report subsystem.
 *
 * Checks the report mode (OFF/AUTO/ON) and generates the report
 * if appropriate. In AUTO mode, only generates when anomalies
 * are detected. Logs the outcome. Safe to call unconditionally.
 */
void finalize_tuning_report();
