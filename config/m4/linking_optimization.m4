#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      - Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

AC_PROG_CC
AC_PROG_CXX

AC_MSG_CHECKING([for LTO])
AC_ARG_ENABLE(lto, AS_HELP_STRING([--enable-lto], [Enable Link Time Optimization]),
	 [
		enable_lto=$enableval
	 ], [enable_lto=yes])

AS_IF([test "x$enable_lto" = "xyes"],
	  [
		case $CC in
			gcc*|g++*)
				AC_SUBST([XLIO_LTO], ["-flto=auto"])
				;;
			clang*|clang++*)
				AC_SUBST([XLIO_LTO], ["-flto=thin"])
				;;
			*)
				AC_MSG_ERROR([Compiler doesn't support link time optimization])
				;;
		esac
		AC_MSG_RESULT([yes])
	  ],
	  [
		AC_SUBST([XLIO_LTO], [""])
		AC_MSG_RESULT([no])
	  ]
)

AC_MSG_CHECKING([for PGO generate])
AC_ARG_WITH([profile-generate],
	[AS_HELP_STRING([--with-profile-generate=DIR], [Path to store profiles for Profile Guided Optimization])],
	[
		COMMON_FLAGS=""
		case $CC in
			gcc*|g++*)
				COMMON_FLAGS+="-fprofile-generate -fprofile-correction -Wno-error=missing-profile"
				COMMON_FLAGS+=" -fprofile-partial-training -fprofile-dir=$withval"
				;;
			clang*|clang++*)
				COMMON_FLAGS+="-fprofile-generate=$withval"
				;;
			*)
				AC_MSG_ERROR([Compiler doesn't support profile guided optimization])
				;;
		esac
		AC_CHECK_LIB([gcov], [__gcov_init], [], [AC_MSG_ERROR([libgcov not found])])
		AC_MSG_RESULT([$withval yes])
		profile_generate=yes
		AC_SUBST([XLIO_PROFILE], ["$COMMON_FLAGS"])
		AC_SUBST([XLIO_GCOV], ["-lgcov"])
	],
	[
		profile_generate=no
		AC_MSG_RESULT([no])
	]
)

AC_MSG_CHECKING([for PGO use])
AC_ARG_WITH([profile-use],
	[AS_HELP_STRING([--with-profile-use=DIR], [Path to read profiles for Profile Guided Optimization])],
	[
		COMMON_FLAGS=""
		case $CC in
			gcc*|g++*)
				COMMON_FLAGS+="-fprofile-use -fprofile-correction -Wno-error=missing-profile"
				COMMON_FLAGS+=" -fprofile-partial-training -fprofile-dir=$withval"
				;;
			clang*|clang++*)
				COMMON_FLAGS+="-fprofile-use=$withval"
				;;
			*)
				AC_MSG_ERROR([Compiler doesn't support profile guided optimization])
				;;
		esac
		AC_MSG_RESULT([$withval yes])
		profile_use=yes
		AC_SUBST([XLIO_PROFILE], ["$COMMON_FLAGS"])
	],
	[
		profile_use=no
		AC_MSG_RESULT([no])
	]
)

AS_IF([test "x$profile_use" = "xyes" && test "x$profile_generate" = "xyes"], [
	AC_MSG_ERROR([** Cannot use both --with-profile-generate and --with-profile-use])
])
