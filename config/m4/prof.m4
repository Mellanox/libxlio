#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2001-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-3-Clause
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

# prof.m4 - Profiling, instrumentation
# 

##########################
# libibprof profiling support
#
AC_DEFUN([PROF_IBPROF_SETUP],
[
AC_ARG_WITH([ibprof],
    AS_HELP_STRING([--with-ibprof],
                   [Search ibprof location (default NO)]),
    [],
    [with_ibprof=no]
)

prj_cv_prof=0
AS_IF([test "x$with_ibprof" == xno],
    [],
    [
    if test -z "$with_ibprof" || test "$with_ibprof" = "yes"; then
        with_ibprof=/usr
    fi

    FUNC_CHECK_WITHDIR([ibprof], [$with_ibprof], [include/ibprof_api.h])

    prj_cv_prof_save_CPPFLAGS="$CPPFLAGS"
    prj_cv_prof_save_CXXFLAGS="$CXXFLAGS"
    prj_cv_prof_save_CFLAGS="$CFLAGS"
    prj_cv_prof_save_LDFLAGS="$LDFLAGS"
    prj_cv_prof_save_LIBS="$LIBS"

    prj_cv_prof_CPPFLAGS="-I$with_ibprof/include"
    prj_cv_prof_LIBS="-libprof"
    prj_cv_prof_LDFLAGS="-L$with_ibprof/lib -Wl,--rpath,$with_ibprof/lib"
    if test -d "$with_ibprof/lib64"; then
        prj_cv_prof_LDFLAGS="-L$with_ibprof/lib64 -Wl,--rpath,$with_ibprof/lib64"
    fi

    CPPFLAGS="$prj_cv_prof_CPPFLAGS $CPPFLAGS"
    CXXFLAGS="$prj_cv_prof_CXXFLAGS $CXXFLAGS"
    LDFLAGS="$prj_cv_prof_LDFLAGS $LDFLAGS"
    LIBS="$prj_cv_prof_LIBS $LIBS"

    AC_LANG_PUSH([C++])
    AC_CHECK_HEADER(
        [ibprof_api.h],
        [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <ibprof_api.h>]],
             [[ibprof_interval_start(1, "start");
               ibprof_interval_end(1);]])],
             [prj_cv_prof=1])
        ])
    AC_LANG_POP()

    CPPFLAGS="$prj_cv_prof_save_CPPFLAGS"
    CXXFLAGS="$prj_cv_prof_save_CXXFLAGS"
    CFLAGS="$prj_cv_prof_save_CFLAGS"
    LDFLAGS="$prj_cv_prof_save_LDFLAGS"
    LIBS="$prj_cv_prof_save_LIBS"
    ])

AC_MSG_CHECKING([for profiling support])
if test "$prj_cv_prof" -ne 0; then
    CPPFLAGS="$CPPFLAGS $prj_cv_prof_CPPFLAGS"
    LDFLAGS="$prj_cv_prof_LDFLAGS $LDFLAGS"
    LIBS="$LIBS $prj_cv_prof_LIBS"
    AC_DEFINE_UNQUOTED([DEFINED_PROF], [1], [Define profiling support])
    AC_MSG_RESULT([yes])
else
    AS_IF([test "x$with_ibprof" == xno],
        [AC_MSG_RESULT([no])],
        [AC_MSG_ERROR([profiling support requested but not present])])
fi
])
