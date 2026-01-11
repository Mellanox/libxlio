/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#pragma once

#include "core/config/descriptors/config_descriptor.h"
#include <experimental/optional>
#include <map>
#include <set>
#include <string>
#include <vector>

/**
 * @brief Resolves short parameter names to full paths
 *
 * Allows users to specify configuration parameters using leaf names or partial paths
 * instead of requiring full hierarchical paths. For example, "memory_limit" can be
 * resolved to "core.resources.memory_limit" if it's unique.
 *
 * When a short name is ambiguous (matches multiple full paths), the resolver
 * throws an error with helpful suggestions showing the shortest unique suffixes.
 */
class key_resolver {
public:
    /**
     * @brief Constructs a key resolver from a config descriptor
     * @param descriptor The config descriptor containing all valid parameter paths
     * @param source_name Name of the configuration source for error messages
     *                    (e.g., "XLIO_INLINE_CONFIG")
     */
    key_resolver(const config_descriptor &descriptor, const std::string &source_name);

    /**
     * @brief Resolves a short key name to its full path
     *
     * Resolution rules:
     * 1. Exact match: If input matches a full path exactly, return it
     * 2. Suffix match: If input matches exactly one path's suffix, return that path
     * 3. Ambiguous: If input matches multiple paths, throw with suggestions
     * 4. Unknown: If input matches no paths, throw with Levenshtein suggestions
     *
     * @param input_key The key to resolve (can be leaf name, partial path, or full path)
     * @return The resolved full path
     * @throws xlio_exception if key is unknown or ambiguous
     */
    std::string resolve(const std::string &input_key) const;

private:
    std::string m_source_name;
    std::set<std::string> m_all_paths;
    std::map<std::string, std::vector<std::string>> m_suffix_index;

    /**
     * @brief Builds the suffix index from all parameter paths
     *
     * For each path like "a.b.c.d", adds entries for:
     * - "d" -> [a.b.c.d]
     * - "c.d" -> [a.b.c.d]
     * - "b.c.d" -> [a.b.c.d]
     * - "a.b.c.d" -> [a.b.c.d]
     *
     * @param descriptor The config descriptor to build index from
     */
    void build_suffix_index(const config_descriptor &descriptor);

    /**
     * @brief Formats an error message for ambiguous keys
     * @param key The ambiguous input key
     * @param matches List of full paths that match
     * @return Formatted error message with suggestions
     */
    std::string format_ambiguity_error(const std::string &key,
                                       const std::vector<std::string> &matches) const;

    /**
     * @brief Finds the shortest unique suffix for a given full path
     * @param full_path The full path to find suffix for
     * @return The shortest suffix that uniquely identifies this path
     */
    std::string find_shortest_unique_suffix(const std::string &full_path) const;

    /**
     * @brief Finds suggestion for unknown key using Levenshtein distance
     * @param key The unknown key
     * @return Suggestion if a close match found, nullopt otherwise
     */
    std::experimental::optional<std::string> find_suggestion(const std::string &key) const;
};
