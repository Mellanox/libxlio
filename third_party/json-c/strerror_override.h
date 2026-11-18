/*
 * Original work:
 *
 * json-c (copyright was originally missing from this file)
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

#ifndef _json_strerror_override_h_
#define _json_strerror_override_h_

/**
 * @file
 * @brief Do not use, json-c internal, may be changed or removed at any time.
 */

#include "config.h"
#include <errno.h>

#include "json_object.h" /* for JSON_EXPORT */

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

JSON_EXPORT char *doca_third_party__json_c_strerror(int errno_in);

#ifndef STRERROR_OVERRIDE_IMPL
#define strerror doca_third_party__json_c_strerror
#endif

#ifdef __cplusplus
}
#endif

#endif /* _json_strerror_override_h_ */
