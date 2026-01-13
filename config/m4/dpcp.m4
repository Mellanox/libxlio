#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
#

# dpcp.m4 - Library to operate with DevX
# 

##########################
# libdpcp usage support
#
AC_DEFUN([DPCP_CAPABILITY_SETUP],
[

get_version_number()
{
    dpcp_cv_token=`grep dpcp_version "${with_dpcp}/include/mellanox/dpcp.h" | sed -n 's/^.*\([[0-9]]\+\.[[0-9]]\+\.[[0-9]]\+\).*$/\1/p' `

    if egrep '^[[0-9]]+\.[[0-9]]+\.[[0-9]]+' <<<"$dpcp_cv_token" >/dev/null 2>&1 ; then
        # It has the correct syntax.
        n=${dpcp_cv_token//[[!0-9]]/ }
        v=(${n//\./ })

        echo "$((${v[[0]]} * 10000 + ${v[[1]]} * 100 + ${v[[2]]}))"
    else
        echo 0
    fi
}

get_min_supported_version()
{
    echo 10143
}

AC_ARG_WITH([dpcp],
    AS_HELP_STRING([--with-dpcp@<:@=DIR@:>@],
                   [Search for dpcp headers and libraries in DIR @<:@default: /usr@:>@]),
    [dpcp_explicitly_specified=yes],
    [dpcp_explicitly_specified=no]
)

AC_ARG_ENABLE([dpcp-shared],
    AS_HELP_STRING([--enable-dpcp-shared],
                   [Link libdpcp dynamically instead of statically @<:@default: static@:>@]),
    [enable_dpcp_shared="$enableval"],
    [enable_dpcp_shared=no]
)

if test "x$prj_cv_directverbs" != x3; then
    AC_MSG_ERROR([RDMA-core subsystem required])
fi

AS_CASE([$srcdir],
  [/*], [top_srcdir=$srcdir],
  [top_srcdir=`cd "$srcdir" && pwd`]
)

prj_cv_dpcp=0
if test -z "$with_dpcp" || test "$with_dpcp" = "yes"; then
    with_dpcp=$ac_abs_top_builddir/submodules/libdpcp/install
fi

# Only check directory exists when --with-dpcp was explicitly specified
if test "x$dpcp_explicitly_specified" = "xyes"; then
    FUNC_CHECK_WITHDIR([dpcp], [$with_dpcp], [include/mellanox/dpcp.h])
fi

prj_cv_dpcp_save_CPPFLAGS="$CPPFLAGS"
prj_cv_dpcp_save_CXXFLAGS="$CXXFLAGS"
prj_cv_dpcp_save_CFLAGS="$CFLAGS"
prj_cv_dpcp_save_LDFLAGS="$LDFLAGS"
prj_cv_dpcp_save_LIBS="$LIBS"

# Make sure libdpcp install directory exists so that compilation checks will not fail due to missing include directory
if test "x$dpcp_explicitly_specified" = "xno"; then
    mkdir -p "$with_dpcp/include"
fi

prj_cv_dpcp_CPPFLAGS="-I$with_dpcp/include"

# Determine library directory
prj_cv_dpcp_libdir="$with_dpcp/lib"
if test -d "$with_dpcp/lib64"; then
    prj_cv_dpcp_libdir="$with_dpcp/lib64"
fi

# Set up linking with dpcp based on static/dynamic choice
prj_cv_dpcp_LIBS_COMMON="-lmlx5 -libverbs -lgcov"
if test "x$enable_dpcp_shared" = "xyes"; then
    # Dynamic linking
    prj_cv_dpcp_SHARED_LIB="$prj_cv_dpcp_libdir/libdpcp.so"
    # When user is not specifying --with-dpcp, i.e. the built-in libdpcp is used,
    # Do not check that the library exists, because it will only be built at the 
    # 'make' stage
    if test "x$dpcp_explicitly_specified" = "xyes" && test ! -f "$prj_cv_dpcp_SHARED_LIB"; then
        AC_MSG_ERROR([libdpcp shared library not found: $prj_cv_dpcp_SHARED_LIB. If static linking with dpcp is desired, remove the --enable-dpcp-shared flag.])
    fi
    prj_cv_dpcp_LIBS="-ldpcp $prj_cv_dpcp_LIBS_COMMON"
    prj_cv_dpcp_LDFLAGS="-L$prj_cv_dpcp_libdir -Wl,--rpath,$prj_cv_dpcp_libdir"
    prj_cv_dpcp_final_libs="-ldpcp"
else
    # Static linking (default)
    prj_cv_dpcp_STATIC_LIB="$prj_cv_dpcp_libdir/libdpcp.a"
    # When user is not specifying --with-dpcp, i.e. the built-in libdpcp is used,
    # Do not check that the library exists, because it will only be built at the 
    # 'make' stage
    if test "x$dpcp_explicitly_specified" = "xyes" && test ! -f "$prj_cv_dpcp_STATIC_LIB"; then
        AC_MSG_ERROR([Static library not found: $prj_cv_dpcp_STATIC_LIB. If dynamic linking with dpcp is desired, use --enable-dpcp-shared.])
    fi
    prj_cv_dpcp_LIBS="$prj_cv_dpcp_STATIC_LIB $prj_cv_dpcp_LIBS_COMMON"
    prj_cv_dpcp_LDFLAGS=""
    # When building XLIO as a static library, We set prj_cv_dpcp_final_libs empty because ar 
    # cannot add a .a file into a .a file.
    # Instead, we add the content of libdpcp.a into libxlio.a by using
    # the rule for libxlio.la: in src/core/Makefile.am
    if test "x$enable_static" = "xyes"; then
        prj_cv_dpcp_final_libs=""
    else
        prj_cv_dpcp_final_libs="$prj_cv_dpcp_STATIC_LIB"
    fi
fi

# Export the static library path for use in src/core/Makefile.am (all-local rule)
AC_SUBST([DPCP_STATIC_LIB], ["$prj_cv_dpcp_STATIC_LIB"])
AM_CONDITIONAL([XLIO_AND_DPCP_ARE_STATIC], [test "x$prj_cv_dpcp_STATIC_LIB" != "x" && test "x$enable_static" = "xyes"])

# Only run header/link checks if dpcp was explicitly specified
# For built-in submodule, we skip these checks since it's not built yet
if test "x$dpcp_explicitly_specified" = "xyes"; then
    CPPFLAGS="$prj_cv_dpcp_CPPFLAGS $CPPFLAGS"
    CXXFLAGS="-std=c++11 $CXXFLAGS"
    LDFLAGS="$prj_cv_dpcp_LDFLAGS $LDFLAGS"
    LIBS="$prj_cv_dpcp_LIBS $LIBS"

    AC_LANG_PUSH([C++])
    AC_CHECK_HEADER(
        [mellanox/dpcp.h],
        [AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <mellanox/dpcp.h>]],
                [[dpcp::provider *provider;
                dpcp::provider::get_instance(provider);]])],
                [prj_cv_dpcp=1])
        ])
    AC_LANG_POP()

    CPPFLAGS="$prj_cv_dpcp_save_CPPFLAGS"
    CXXFLAGS="$prj_cv_dpcp_save_CXXFLAGS"
    CFLAGS="$prj_cv_dpcp_save_CFLAGS"
    LDFLAGS="$prj_cv_dpcp_save_LDFLAGS"
    LIBS="$prj_cv_dpcp_save_LIBS"

    AC_MSG_CHECKING([for dpcp support])
    if test "$prj_cv_dpcp" -ne 0; then
        CPPFLAGS="$CPPFLAGS $prj_cv_dpcp_CPPFLAGS"
        LDFLAGS="$prj_cv_dpcp_LDFLAGS $LDFLAGS"
        AC_SUBST([DPCP_LIBS], ["$prj_cv_dpcp_final_libs"])
        dpcp_version_number=($(get_version_number))
        min_supported_version=($(get_min_supported_version))

        if test "$dpcp_version_number" -ge "$min_supported_version"; then
            AC_DEFINE_UNQUOTED([DEFINED_DPCP_MIN], [$min_supported_version], [Define to DPCP version number (major * 10000 + minor * 100 + patch)])
            if test "x$enable_dpcp_shared" = "xyes"; then
                AC_MSG_RESULT([yes (dynamic linking)])
            else
                AC_MSG_RESULT([yes (static linking)])
            fi
        else
            AC_MSG_ERROR([found incompatible dpcp version $dpcp_version_number (min supported version $min_supported_version) ])
        fi
    else
        AC_MSG_ERROR([dpcp support requested but not present])
    fi
else
    # Using built-in submodule - skip checks, assume dpcp will be built
    AC_MSG_CHECKING([for dpcp support])
    AC_MSG_RESULT([using built-in submodule (will be built)])
    
    # Set up paths for when it is built
    CPPFLAGS="$CPPFLAGS $prj_cv_dpcp_CPPFLAGS"
    LDFLAGS="$prj_cv_dpcp_LDFLAGS $LDFLAGS"
    AC_SUBST([DPCP_LIBS], ["$prj_cv_dpcp_final_libs"])
    
    # Use a placeholder version - the real check happens at make time
    min_supported_version=($(get_min_supported_version))
    AC_DEFINE_UNQUOTED([DEFINED_DPCP_MIN], [$min_supported_version], [Define to DPCP version number (major * 10000 + minor * 100 + patch)])
fi
])
