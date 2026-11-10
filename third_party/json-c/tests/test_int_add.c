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

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdio.h>

#include "json.h"

int main(int argc, char **argv)
{
	json_object *tmp = doca_third_party_json_object_new_int(123);
	doca_third_party_json_object_int_inc(tmp, 123);
	assert(doca_third_party_json_object_get_int(tmp) == 246);
	doca_third_party_json_object_put(tmp);
	printf("INT ADD PASSED\n");
	tmp = doca_third_party_json_object_new_int(INT32_MAX);
	doca_third_party_json_object_int_inc(tmp, 100);
	assert(doca_third_party_json_object_get_int(tmp) == INT32_MAX);
	assert(doca_third_party_json_object_get_int64(tmp) == (int64_t)INT32_MAX + 100L);
	doca_third_party_json_object_put(tmp);
	printf("INT ADD OVERFLOW PASSED\n");
	tmp = doca_third_party_json_object_new_int(INT32_MIN);
	doca_third_party_json_object_int_inc(tmp, -100);
	assert(doca_third_party_json_object_get_int(tmp) == INT32_MIN);
	assert(doca_third_party_json_object_get_int64(tmp) == (int64_t)INT32_MIN - 100L);
	doca_third_party_json_object_put(tmp);
	printf("INT ADD UNDERFLOW PASSED\n");
	tmp = doca_third_party_json_object_new_int64(321321321);
	doca_third_party_json_object_int_inc(tmp, 321321321);
	assert(doca_third_party_json_object_get_int(tmp) == 642642642);
	doca_third_party_json_object_put(tmp);
	printf("INT64 ADD PASSED\n");
	tmp = doca_third_party_json_object_new_int64(INT64_MAX);
	doca_third_party_json_object_int_inc(tmp, 100);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MAX);
	assert(doca_third_party_json_object_get_uint64(tmp) == (uint64_t)INT64_MAX + 100U);
	doca_third_party_json_object_int_inc(tmp, -100);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MAX);
	assert(doca_third_party_json_object_get_uint64(tmp) == (uint64_t)INT64_MAX);
	doca_third_party_json_object_put(tmp);
	printf("INT64 ADD OVERFLOW PASSED\n");
	tmp = doca_third_party_json_object_new_int64(INT64_MIN);
	doca_third_party_json_object_int_inc(tmp, -100);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MIN);
	doca_third_party_json_object_int_inc(tmp, 100);
	assert(doca_third_party_json_object_get_int64(tmp) != INT64_MIN);
	doca_third_party_json_object_put(tmp);
	printf("INT64 ADD UNDERFLOW PASSED\n");
	// uint64 + negative int64--> negative int64
	tmp = doca_third_party_json_object_new_uint64(400);
	doca_third_party_json_object_int_inc(tmp, -200);
	assert(doca_third_party_json_object_get_int64(tmp) == 200);
	assert(doca_third_party_json_object_get_uint64(tmp) == 200);
	doca_third_party_json_object_int_inc(tmp, 200);
	assert(doca_third_party_json_object_get_int64(tmp) == 400);
	assert(doca_third_party_json_object_get_uint64(tmp) == 400);
	doca_third_party_json_object_put(tmp);
	printf("UINT64 ADD PASSED\n");
	tmp = doca_third_party_json_object_new_uint64(UINT64_MAX-50);
	doca_third_party_json_object_int_inc(tmp, 100);
	assert(doca_third_party_json_object_get_int64(tmp) == INT64_MAX);
	assert(doca_third_party_json_object_get_uint64(tmp) == UINT64_MAX);
	doca_third_party_json_object_put(tmp);
	printf("UINT64 ADD OVERFLOW PASSED\n");
	tmp = doca_third_party_json_object_new_uint64(100);
	doca_third_party_json_object_int_inc(tmp, -200);
	assert(doca_third_party_json_object_get_int64(tmp) == -100);
	assert(doca_third_party_json_object_get_uint64(tmp) == 0);
	doca_third_party_json_object_put(tmp);
	printf("UINT64 ADD UNDERFLOW PASSED\n");

	printf("PASSED\n");
	return 0;
}
