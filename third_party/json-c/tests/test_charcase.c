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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "json_tokener.h"

static void test_case_parse(void);

int main(int argc, char **argv)
{
	MC_SET_DEBUG(1);

	test_case_parse();

	return 0;
}

/* make sure only lowercase forms are parsed in strict mode */
static void test_case_parse(void)
{
	struct json_tokener *tok;
	json_object *new_obj;

	tok = doca_third_party_json_tokener_new();
	doca_third_party_json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

	new_obj = doca_third_party_json_tokener_parse_ex(tok, "True", 4);
	assert(new_obj == NULL);

	new_obj = doca_third_party_json_tokener_parse_ex(tok, "False", 5);
	assert(new_obj == NULL);

	new_obj = doca_third_party_json_tokener_parse_ex(tok, "Null", 4);
	assert(new_obj == NULL);

	printf("OK\n");

	doca_third_party_json_tokener_free(tok);
}
