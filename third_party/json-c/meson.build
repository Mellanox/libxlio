#
# Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

subdir('config')
third_party_include += include_directories('config')
third_party_include += include_directories('.')

json_config = configuration_data()
if conf.has('HAVE_INTTYPES_H')
  json_config.set10('JSON_C_HAVE_INTTYPES_H', true)
endif
json_config_h = configure_file(
  configuration: json_config,
  output: 'json_config.h',
)

public_headers = [
  json_config_h,
  'arraylist.h',
  'debug.h',
  'json.h',
  'json_c_version.h',
  'json_inttypes.h',
  'json_object.h',
  'json_object_iterator.h',
  'json_pointer.h',
  'json_tokener.h',
  'json_types.h',
  'json_util.h',
  'json_visit.h',
  'linkhash.h',
  'printbuf.h',
]

third_party_sources = files([
  'arraylist.c',
  'debug.c',
  'json_c_version.c',
  'json_object.c',
  'json_object_iterator.c',
  'json_pointer.c',
  'json_tokener.c',
  'json_util.c',
  'json_visit.c',
  'linkhash.c',
  'printbuf.c',
  'random_seed.c',
  'strerror_override.c',
])

if is_compiler_msvc
	third_party_c_args += [
		# mark that this is windows OS
		'/DWIN32',
		# ignore conversion from 'type1' to 'type2', possible loss of data
		'/wd4244',
		# ignore conversion from 'size_t' to 'type', possible loss of data
		'/wd4267',
		# ignore use of deprecated functions
		'/wd4996',
	]
else
	third_party_dependencies += [
		dependency_mlib,
		dependency_threads,
	]

	third_party_c_args += [
		'-Wno-double-promotion',
		'-Wno-format',
		'-Wno-format-security',
		'-Wno-null-dereference',
		'-Wno-format-nonliteral',
		'-Wno-missing-declarations',
		'-Wno-missing-prototypes',
		'-Wno-old-style-definition',
		'-Wno-strict-prototypes',
		'-Wno-suggest-attribute=format',
	]

	if is_compiler_clang
		third_party_c_args += ['-Wno-missing-variable-declarations']
	endif
endif
