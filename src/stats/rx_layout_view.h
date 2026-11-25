/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */
#ifndef XLIO_RX_LAYOUT_VIEW_H
#define XLIO_RX_LAYOUT_VIEW_H
#include <string>
int print_rx_analysis(int pid, const std::string &directory, unsigned samples, int interval,
                      int cycles, const std::string &csv_path = {});
const char *rx_analysis_help();
#endif
