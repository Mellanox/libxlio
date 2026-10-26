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
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#include "json.h"
#include "parse_flags.h"

static int sort_fn(const void *j1, const void *j2)
{
	json_object *const *jso1, *const *jso2;
	int i1, i2;

	jso1 = (json_object *const *)j1;
	jso2 = (json_object *const *)j2;
	if (!*jso1 && !*jso2)
		return 0;
	if (!*jso1)
		return -1;
	if (!*jso2)
		return 1;

	i1 = doca_third_party_json_object_get_int(*jso1);
	i2 = doca_third_party_json_object_get_int(*jso2);

	return i1 - i2;
}

#ifdef TEST_FORMATTED
static const char *to_json_string(json_object *obj, int flags)
{
	size_t length;
	char *copy;
	const char *result;

	result = doca_third_party_json_object_to_json_string_length(obj, flags, &length);
	copy = strdup(result);
	if (copy == NULL)
		printf("to_json_string: Allocation failed!\n");
	else
	{
		result = doca_third_party_json_object_to_json_string_ext(obj, flags);
		if (length != strlen(result))
			printf("to_json_string: Length mismatch!\n");
		if (strcmp(copy, result) != 0)
			printf("to_json_string: Comparison Failed!\n");
		free(copy);
	}
	return result;
}
#define doca_third_party_json_object_to_json_string(obj) to_json_string(obj, sflags)
#else
/* no special define */
#endif

json_object *make_array(void);
json_object *make_array(void)
{
	json_object *my_array;

	my_array = doca_third_party_json_object_new_array();
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(1));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(2));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(3));
	doca_third_party_json_object_array_put_idx(my_array, 4, doca_third_party_json_object_new_int(5));
	doca_third_party_json_object_array_put_idx(my_array, 3, doca_third_party_json_object_new_int(4));
	doca_third_party_json_object_array_put_idx(my_array, 6, doca_third_party_json_object_new_int(7));

	return my_array;
}

void test_array_del_idx(void);
void test_array_del_idx(void)
{
	int rc;
	size_t ii;
	size_t orig_array_len;
	json_object *my_array;
#ifdef TEST_FORMATTED
	int sflags = 0;
#endif

	my_array = make_array();
	orig_array_len = doca_third_party_json_object_array_length(my_array);

	printf("my_array=\n");
	for (ii = 0; ii < doca_third_party_json_object_array_length(my_array); ii++)
	{
		json_object *obj = doca_third_party_json_object_array_get_idx(my_array, ii);
		printf("\t[%d]=%s\n", (int)ii, doca_third_party_json_object_to_json_string(obj));
	}
	printf("my_array.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_array));

	for (ii = 0; ii < orig_array_len; ii++)
	{
		rc = doca_third_party_json_object_array_del_idx(my_array, 0, 1);
		printf("after del_idx(0,1)=%d, my_array.to_string()=%s\n", rc,
		       doca_third_party_json_object_to_json_string(my_array));
	}

	/* One more time, with the empty array: */
	rc = doca_third_party_json_object_array_del_idx(my_array, 0, 1);
	printf("after del_idx(0,1)=%d, my_array.to_string()=%s\n", rc,
	       doca_third_party_json_object_to_json_string(my_array));

	doca_third_party_json_object_put(my_array);

	/* Delete all array indexes at once */
	my_array = make_array();
	rc = doca_third_party_json_object_array_del_idx(my_array, 0, orig_array_len);
	printf("after del_idx(0,%d)=%d, my_array.to_string()=%s\n", (int)orig_array_len, rc,
	       doca_third_party_json_object_to_json_string(my_array));

	doca_third_party_json_object_put(my_array);

	/* Delete *more* than all array indexes at once */
	my_array = make_array();
	rc = doca_third_party_json_object_array_del_idx(my_array, 0, orig_array_len + 1);
	printf("after del_idx(0,%d)=%d, my_array.to_string()=%s\n", (int)(orig_array_len + 1), rc,
	       doca_third_party_json_object_to_json_string(my_array));

	doca_third_party_json_object_put(my_array);

	/* Delete some array indexes, then add more */
	my_array = make_array();
	rc = doca_third_party_json_object_array_del_idx(my_array, 0, orig_array_len - 1);
	printf("after del_idx(0,%d)=%d, my_array.to_string()=%s\n", (int)(orig_array_len - 1), rc,
	       doca_third_party_json_object_to_json_string(my_array));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_string("s1"));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_string("s2"));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_string("s3"));

	printf("after adding more entries, my_array.to_string()=%s\n",
	       doca_third_party_json_object_to_json_string(my_array));
	doca_third_party_json_object_put(my_array);
}

void test_array_list_expand_internal(void);
void test_array_list_expand_internal(void)
{
	int rc;
	size_t ii;
	size_t idx;
	json_object *my_array;
#ifdef TEST_FORMATTED
	int sflags = 0;
#endif

	my_array = make_array();
	printf("my_array=\n");
	for (ii = 0; ii < doca_third_party_json_object_array_length(my_array); ii++)
	{
		json_object *obj = doca_third_party_json_object_array_get_idx(my_array, ii);
		printf("\t[%d]=%s\n", (int)ii, doca_third_party_json_object_to_json_string(obj));
	}
	printf("my_array.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_array));

	/* Put iNdex < array->size, no expand. */
	rc = doca_third_party_json_object_array_put_idx(my_array, 5, doca_third_party_json_object_new_int(6));
	printf("put_idx(5,6)=%d\n", rc);

	/* array->size < Put Index < array->size * 2 <= SIZE_T_MAX, the size = array->size * 2. */
	idx = ARRAY_LIST_DEFAULT_SIZE * 2 - 1;
	rc = doca_third_party_json_object_array_put_idx(my_array, idx, doca_third_party_json_object_new_int(0));
	printf("put_idx(%d,0)=%d\n", (int)(idx), rc);

	/* array->size * 2 < Put Index, the size = Put Index. */
	idx = ARRAY_LIST_DEFAULT_SIZE * 2 * 2 + 1;
	rc = doca_third_party_json_object_array_put_idx(my_array, idx, doca_third_party_json_object_new_int(0));
	printf("put_idx(%d,0)=%d\n", (int)(idx), rc);

	/* SIZE_T_MAX <= Put Index, it will fail and the size will no change. */
	idx = SIZE_MAX; // SIZE_MAX = SIZE_T_MAX
	json_object *tmp = doca_third_party_json_object_new_int(10);
	rc = doca_third_party_json_object_array_put_idx(my_array, idx, tmp);
	printf("put_idx(SIZE_T_MAX,0)=%d\n", rc);
	if (rc == -1)
	{
		doca_third_party_json_object_put(tmp);
	}

	doca_third_party_json_object_put(my_array);
}

void test_array_insert_idx(void);
void test_array_insert_idx(void)
{
	json_object *my_array;
	struct json_object *jo1;

	my_array = doca_third_party_json_object_new_array();
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(1));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(2));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(5));

	doca_third_party_json_object_array_insert_idx(my_array, 2, doca_third_party_json_object_new_int(4));
	jo1 = doca_third_party_json_tokener_parse("[1, 2, 4, 5]");
	assert(1 == doca_third_party_json_object_equal(my_array, jo1));
	doca_third_party_json_object_put(jo1);

	doca_third_party_json_object_array_insert_idx(my_array, 2, doca_third_party_json_object_new_int(3));

	jo1 = doca_third_party_json_tokener_parse("[1, 2, 3, 4, 5]");
	assert(1 == doca_third_party_json_object_equal(my_array, jo1));
	doca_third_party_json_object_put(jo1);

	doca_third_party_json_object_array_insert_idx(my_array, 5, doca_third_party_json_object_new_int(6));

	jo1 = doca_third_party_json_tokener_parse("[1, 2, 3, 4, 5, 6]");
	assert(1 == doca_third_party_json_object_equal(my_array, jo1));
	doca_third_party_json_object_put(jo1);

	doca_third_party_json_object_array_insert_idx(my_array, 7, doca_third_party_json_object_new_int(8));
	jo1 = doca_third_party_json_tokener_parse("[1, 2, 3, 4, 5, 6, null, 8]");
	assert(1 == doca_third_party_json_object_equal(my_array, jo1));
	doca_third_party_json_object_put(jo1);

	doca_third_party_json_object_put(my_array);
}

int main(int argc, char **argv)
{
	json_object *my_string, *my_int, *my_null, *my_object, *my_array;
	size_t i;
#ifdef TEST_FORMATTED
	int sflags = 0;
#endif

	MC_SET_DEBUG(1);

#ifdef TEST_FORMATTED
	sflags = parse_flags(argc, argv);
#endif

	my_string = doca_third_party_json_object_new_string("\t");
	printf("my_string=%s\n", doca_third_party_json_object_get_string(my_string));
	printf("my_string.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_string));
	doca_third_party_json_object_put(my_string);

	my_string = doca_third_party_json_object_new_string("\\");
	printf("my_string=%s\n", doca_third_party_json_object_get_string(my_string));
	printf("my_string.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_string));
	doca_third_party_json_object_put(my_string);

	my_string = doca_third_party_json_object_new_string("/");
	printf("my_string=%s\n", doca_third_party_json_object_get_string(my_string));
	printf("my_string.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_string));
	printf("my_string.to_string(NOSLASHESCAPE)=%s\n",
	       doca_third_party_json_object_to_json_string_ext(my_string, JSON_C_TO_STRING_NOSLASHESCAPE));
	doca_third_party_json_object_put(my_string);

	my_string = doca_third_party_json_object_new_string("/foo/bar/baz");
	printf("my_string=%s\n", doca_third_party_json_object_get_string(my_string));
	printf("my_string.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_string));
	printf("my_string.to_string(NOSLASHESCAPE)=%s\n",
	       doca_third_party_json_object_to_json_string_ext(my_string, JSON_C_TO_STRING_NOSLASHESCAPE));
	doca_third_party_json_object_put(my_string);

	my_string = doca_third_party_json_object_new_string("foo");
	printf("my_string=%s\n", doca_third_party_json_object_get_string(my_string));
	printf("my_string.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_string));

	my_int = doca_third_party_json_object_new_int(9);
	printf("my_int=%d\n", doca_third_party_json_object_get_int(my_int));
	printf("my_int.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_int));

	my_null = doca_third_party_json_object_new_null();
	printf("my_null.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_null));

	my_array = doca_third_party_json_object_new_array();
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(1));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(2));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(3));
	doca_third_party_json_object_array_put_idx(my_array, 4, doca_third_party_json_object_new_int(5));
	printf("my_array=\n");
	for (i = 0; i < doca_third_party_json_object_array_length(my_array); i++)
	{
		json_object *obj = doca_third_party_json_object_array_get_idx(my_array, i);
		printf("\t[%d]=%s\n", (int)i, doca_third_party_json_object_to_json_string(obj));
	}
	printf("my_array.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_array));

	doca_third_party_json_object_put(my_array);

	test_array_insert_idx();

	test_array_del_idx();
	test_array_list_expand_internal();

	my_array = doca_third_party_json_object_new_array_ext(5);
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(3));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(1));
	doca_third_party_json_object_array_add(my_array, doca_third_party_json_object_new_int(2));
	doca_third_party_json_object_array_put_idx(my_array, 4, doca_third_party_json_object_new_int(0));
	printf("my_array=\n");
	for (i = 0; i < doca_third_party_json_object_array_length(my_array); i++)
	{
		json_object *obj = doca_third_party_json_object_array_get_idx(my_array, i);
		printf("\t[%d]=%s\n", (int)i, doca_third_party_json_object_to_json_string(obj));
	}
	printf("my_array.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_array));
	doca_third_party_json_object_array_sort(my_array, sort_fn);
	printf("my_array=\n");
	for (i = 0; i < doca_third_party_json_object_array_length(my_array); i++)
	{
		json_object *obj = doca_third_party_json_object_array_get_idx(my_array, i);
		printf("\t[%d]=%s\n", (int)i, doca_third_party_json_object_to_json_string(obj));
	}
	printf("my_array.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_array));

	json_object *one = doca_third_party_json_object_new_int(1);
	json_object *result = doca_third_party_json_object_array_bsearch(one, my_array, sort_fn);
	printf("find json_object(1) in my_array successfully: %s\n",
	       doca_third_party_json_object_to_json_string(result));
	doca_third_party_json_object_put(one);

	my_object = doca_third_party_json_object_new_object();
	int rc = doca_third_party_json_object_object_add(my_object, "abc", my_object);
	if (rc != -1)
	{
		printf("ERROR: able to successfully add object to itself!\n");
		fflush(stdout);
	}
	doca_third_party_json_object_object_add(my_object, "abc", doca_third_party_json_object_new_int(12));
	doca_third_party_json_object_object_add(my_object, "foo", doca_third_party_json_object_new_string("bar"));
	doca_third_party_json_object_object_add(my_object, "bool0", doca_third_party_json_object_new_boolean(0));
	doca_third_party_json_object_object_add(my_object, "bool1", doca_third_party_json_object_new_boolean(1));
	doca_third_party_json_object_object_add(my_object, "baz", doca_third_party_json_object_new_string("bang"));

	json_object *baz_obj = doca_third_party_json_object_new_string("fark");
	doca_third_party_json_object_get(baz_obj);
	doca_third_party_json_object_object_add(my_object, "baz", baz_obj);
	doca_third_party_json_object_object_del(my_object, "baz");

	/* baz_obj should still be valid */
	printf("baz_obj.to_string()=%s\n", doca_third_party_json_object_to_json_string(baz_obj));
	doca_third_party_json_object_put(baz_obj);

	/*json_object_object_add(my_object, "arr", my_array);*/
	printf("my_object=\n");
	doca_third_party_json_object_object_foreach(my_object, key, val)
	{
		printf("\t%s: %s\n", key, doca_third_party_json_object_to_json_string(val));
	}

	json_object *empty_array = doca_third_party_json_object_new_array();
	json_object *empty_obj = doca_third_party_json_object_new_object();
	doca_third_party_json_object_object_add(my_object, "empty_array", empty_array);
	doca_third_party_json_object_object_add(my_object, "empty_obj", empty_obj);
	printf("my_object.to_string()=%s\n", doca_third_party_json_object_to_json_string(my_object));

	doca_third_party_json_object_put(my_array);
	my_array = doca_third_party_json_object_new_array_ext(INT_MIN + 1);
	if (my_array != NULL)
	{
		printf("ERROR: able to allocate an array of negative size!\n");
		fflush(stdout);
		doca_third_party_json_object_put(my_array);
		my_array = NULL;
	}

#if SIZEOF_SIZE_T == SIZEOF_INT
	my_array = doca_third_party_json_object_new_array_ext(INT_MAX / 2 + 2);
	if (my_array != NULL)
	{
		printf("ERROR: able to allocate an array of insufficient size!\n");
		fflush(stdout);
		doca_third_party_json_object_put(my_array);
		my_array = NULL;
	}
#endif

	doca_third_party_json_object_put(my_string);
	doca_third_party_json_object_put(my_int);
	doca_third_party_json_object_put(my_null);
	doca_third_party_json_object_put(my_object);
	doca_third_party_json_object_put(my_array);

	return EXIT_SUCCESS;
}
