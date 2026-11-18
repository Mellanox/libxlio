/*
 * Original work:
 *
 * $Id: json.h,v 1.6 2006/01/26 02:16:28 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2009 Hewlett-Packard Development Company, L.P.
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
 * This is a workaround header so that other modules will include <json-c/json.h>
 * as if they are using upstream, and will still find our file.
 */

#ifdef _json_h_
#error "regular" json-c is in the include path and will conflict with the version of DOCA!
#endif

#ifndef _doca_json_h_
#define _doca_json_h_

#ifdef __cplusplus
extern "C" {
#endif

#include "arraylist.h"
#include "debug.h"
#include "json_c_version.h"
#include "json_object.h"
#include "json_object_iterator.h"
#include "json_patch.h"
#include "json_pointer.h"
#include "json_tokener.h"
#include "json_util.h"
#include "linkhash.h"

#ifdef __cplusplus
}
#endif

#endif
