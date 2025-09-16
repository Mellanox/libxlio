/*
 * Original work:
 *
 * Copyright (c) 2012,2017 Eric Haszlakiewicz
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 * Modified Work:
 *
 * Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

/**
 * @file
 * @brief Methods for retrieving the json-c version.
 */
#ifndef _json_c_version_h_
#define _json_c_version_h_

#ifdef __cplusplus
extern "C" {
#endif

#define JSON_C_MAJOR_VERSION 0
#define JSON_C_MINOR_VERSION 17
#define JSON_C_MICRO_VERSION 0
#define JSON_C_VERSION_NUM \
	((JSON_C_MAJOR_VERSION << 16) | (JSON_C_MINOR_VERSION << 8) | JSON_C_MICRO_VERSION)
#define JSON_C_VERSION "0.17"

#ifndef JSON_EXPORT
#if defined(_MSC_VER) && defined(JSON_C_DLL)
#define JSON_EXPORT __declspec(dllexport)
#else
#define JSON_EXPORT extern
#endif
#endif

/**
 * @see JSON_C_VERSION
 * @return the version of the json-c library as a string
 */
JSON_EXPORT const char *doca_third_party_json_c_version(void); /* Returns JSON_C_VERSION */

/**
 * The json-c version encoded into an int, with the low order 8 bits
 * being the micro version, the next higher 8 bits being the minor version
 * and the next higher 8 bits being the major version.
 * For example, 7.12.99 would be 0x00070B63.
 *
 * @see JSON_C_VERSION_NUM
 * @return the version of the json-c library as an int
 */
JSON_EXPORT int doca_third_party_json_c_version_num(void); /* Returns JSON_C_VERSION_NUM */

#ifdef __cplusplus
}
#endif

#endif
