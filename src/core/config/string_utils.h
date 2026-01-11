/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include <string>
#include <vector>

/**
 * @brief String utility functions for configuration subsystem
 *
 * Provides centralized, reusable string manipulation functions
 * to avoid code duplication across the configuration subsystem.
 */
namespace string_utils {

/**
 * @brief Splits a string by a delimiter character
 *
 * Splits the input string into tokens separated by the delimiter.
 * Empty tokens are skipped.
 *
 * @param s The string to split
 * @param delimiter The character to split on
 * @return Vector of non-empty tokens
 */
std::vector<std::string> split(const std::string &s, char delimiter);

/**
 * @brief Calculates the Levenshtein distance between two strings.
 *
 * The Levenshtein distance is the number of single-character edits
 * (insertions, deletions, or substitutions) required to change one
 * string into the other. Used for "Did you mean?" suggestions.
 *
 * @param s1 The first string.
 * @param s2 The second string.
 * @return The Levenshtein distance between the two strings.
 */
size_t levenshtein_distance(const std::string &s1, const std::string &s2);

/**
 * @brief Maximum Levenshtein distance for "Did you mean?" suggestions
 *
 * Keys with edit distance greater than this threshold won't be suggested.
 */
static const size_t MAX_LEVENSHTEIN_DISTANCE = 3;

} // namespace string_utils
