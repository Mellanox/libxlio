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
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_object.h"
#include "json_object_iterator.h"
#include "json_tokener.h"

int main(int atgc, char **argv)
{
	const char *input = "{\n\
		\"string_of_digits\": \"123\",\n\
		\"regular_number\": 222,\n\
		\"decimal_number\": 99.55,\n\
		\"boolean_true\": true,\n\
		\"boolean_false\": false,\n\
		\"big_number\": 2147483649,\n\
		\"a_null\": null,\n\
		}";

	struct json_object *new_obj;
	struct json_object_iterator it;
	struct json_object_iterator itEnd;

	it = doca_third_party_json_object_iter_init_default();
	new_obj = doca_third_party_json_tokener_parse(input);
	it = doca_third_party_json_object_iter_begin(new_obj);
	itEnd = doca_third_party_json_object_iter_end(new_obj);

	while (!doca_third_party_json_object_iter_equal(&it, &itEnd))
	{
		printf("%s\n", doca_third_party_json_object_iter_peek_name(&it));
		printf("%s\n", doca_third_party_json_object_to_json_string(doca_third_party_json_object_iter_peek_value(&it)));
		doca_third_party_json_object_iter_next(&it);
	}

	doca_third_party_json_object_put(new_obj);

	return 0;
}
