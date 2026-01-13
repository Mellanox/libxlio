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
    echo 10161
}

AC_ARG_ENABLE([dpcp-shared],
    AS_HELP_STRING([--enable-dpcp-shared],
                   [Link libdpcp dynamically instead of statically @<:@default: static@:>@]),
    [enable_dpcp_shared="$enableval"],
    [enable_dpcp_shared=no]
)

if test "x$prj_cv_directverbs" != x3; then
    AC_MSG_ERROR([RDMA-core subsystem required])
fi

if test "x$enable_dpcp_shared" = "xyes"; then
    DPCP_CMAKE_STATIC=OFF
else
    DPCP_CMAKE_STATIC=ON
fi

# Define conditional for building built-in libdpcp
AM_CONDITIONAL([BUILD_BUILTIN_DPCP], [test "x$dpcp_explicitly_specified" != "xyes"])


DPCP_SOURCE_DIR=
DPCP_BUILD_DIR=
DPCP_INSTALL_DIR=
DPCP_CMAKE_IN_SOURCE=no

if test "x$dpcp_explicitly_specified" = "xno"; then
    if test ! -f "$srcdir/submodules/libdpcp/CMakeLists.txt"; then
        AC_MSG_ERROR([$srcdir/submodules/libdpcp/CMakeLists.txt not found, did you run ./autogen.sh?
                      This should have populated $srcdir/submodules/libdpcp by running 'git submodule update --init --recursive'.
                      To use libdpcp from another location, specify --with-dpcp=DIR])
    fi

    AC_PATH_PROGS([CMAKE], [cmake3 cmake], [])
    if test -z "$CMAKE"; then
        AC_MSG_ERROR([CMake is required to configure the built-in libdpcp])
    fi

    dpcp_top_srcdir=`cd "$srcdir" && pwd`
    DPCP_SOURCE_DIR="$dpcp_top_srcdir/submodules/libdpcp"
    if test "x$dpcp_top_srcdir" = "x$ac_pwd"; then
        DPCP_BUILD_DIR="$DPCP_SOURCE_DIR"
        DPCP_CMAKE_IN_SOURCE=yes
    else
        DPCP_BUILD_DIR="$ac_pwd/submodules/libdpcp"
    fi
    DPCP_INSTALL_DIR="$DPCP_BUILD_DIR/install"
    with_dpcp="$DPCP_INSTALL_DIR"

    AS_MKDIR_P(["$DPCP_BUILD_DIR"])
    AC_MSG_NOTICE([configuring built-in libdpcp with CMake])
    AC_MSG_NOTICE([libdpcp source directory: $DPCP_SOURCE_DIR])
    AC_MSG_NOTICE([libdpcp build directory: $DPCP_BUILD_DIR])
    AC_MSG_NOTICE([libdpcp CMake flags: ${with_dpcp_flags:-none}])

    (
        cd "$DPCP_BUILD_DIR" || exit 1
        set -f
        set -- $with_dpcp_flags
        set +f
        CC="$CC" CXX="$CXX" "$CMAKE" "$[]@" \
            "-DCMAKE_INSTALL_PREFIX:PATH=$DPCP_INSTALL_DIR" \
            "-DCMAKE_INSTALL_LIBDIR:PATH=lib" \
            "-DDPCP_STATIC:BOOL=$DPCP_CMAKE_STATIC" \
            "$DPCP_SOURCE_DIR"
    ) || AC_MSG_ERROR([failed to configure the built-in libdpcp with CMake])

    DPCP_SUMMARY="built-in CMake (DPCP_STATIC=$DPCP_CMAKE_STATIC)"
else
    DPCP_SUMMARY="external ($with_dpcp)"
fi
DPCP_CMAKE_FLAGS_SUMMARY="${with_dpcp_flags:-none}"

AC_SUBST([CMAKE])
AC_SUBST([DPCP_SOURCE_DIR])
AC_SUBST([DPCP_BUILD_DIR])
AC_SUBST([DPCP_INSTALL_DIR])
AC_SUBST([DPCP_CMAKE_STATIC])
AC_SUBST([DPCP_CMAKE_FLAGS], ["$with_dpcp_flags"])
AM_CONDITIONAL([BUILTIN_DPCP_STATIC], [test "x$dpcp_explicitly_specified" = "xno" && test "x$DPCP_CMAKE_STATIC" = "xON"])
AM_CONDITIONAL([DPCP_CMAKE_IN_SOURCE], [test "x$DPCP_CMAKE_IN_SOURCE" = "xyes"])

prj_cv_dpcp=0
# Only check directory exists when --with-dpcp was explicitly specified
if test "x$dpcp_explicitly_specified" = "xyes"; then
    FUNC_CHECK_WITHDIR([dpcp], [$with_dpcp], [include/mellanox/dpcp.h])
    with_dpcp=`cd "$with_dpcp" && pwd`
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
if test "x$enable_dpcp_shared" = "xyes"; then
    prj_cv_dpcp_libname="libdpcp.so"
else
    prj_cv_dpcp_libname="libdpcp.a"
fi

if test "x$dpcp_explicitly_specified" = "xyes"; then
    prj_cv_dpcp_libdir=
    for dpcp_libdir in "$with_dpcp/lib" "$with_dpcp/lib64"; do
        if test -f "$dpcp_libdir/$prj_cv_dpcp_libname"; then
            prj_cv_dpcp_libdir="$dpcp_libdir"
            break
        fi
    done
    if test -z "$prj_cv_dpcp_libdir"; then
        AC_MSG_ERROR([$prj_cv_dpcp_libname not found in $with_dpcp/lib or $with_dpcp/lib64])
    fi
else
    prj_cv_dpcp_libdir="$with_dpcp/lib"
fi

# Set up linking with dpcp based on static/dynamic choice
prj_cv_dpcp_LIBS_COMMON="-lmlx5 -libverbs -lgcov"
if test "x$enable_dpcp_shared" = "xyes"; then
    # Dynamic linking
    prj_cv_dpcp_SHARED_LIB="$prj_cv_dpcp_libdir/libdpcp.so"
    prj_cv_dpcp_LIBS="-ldpcp $prj_cv_dpcp_LIBS_COMMON"
    prj_cv_dpcp_LDFLAGS="-L$prj_cv_dpcp_libdir -Wl,--rpath,$prj_cv_dpcp_libdir"
    prj_cv_dpcp_final_libs="-ldpcp"
else
    # Static linking (default)
    prj_cv_dpcp_STATIC_LIB="$prj_cv_dpcp_libdir/libdpcp.a"
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

DPCP_LIB_DEPENDENCY=
if test "x$dpcp_explicitly_specified" = "xno"; then
    if test "x$enable_dpcp_shared" = "xyes"; then
        DPCP_LIB_DEPENDENCY="$prj_cv_dpcp_SHARED_LIB"
    else
        DPCP_LIB_DEPENDENCY="$prj_cv_dpcp_STATIC_LIB"
    fi
fi
AC_SUBST([DPCP_LIB_DEPENDENCY])

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
