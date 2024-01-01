#
# Copyright © 2001-2024 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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

# compiler.m4 - Configure compiler capabilities
#


# Check compiler specific attributes
# Usage: CHECK_COMPILER_ATTRIBUTE([attribute], [program], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_COMPILER_ATTRIBUTE], [
    AC_CACHE_VAL(prj_cv_attribute_[$1], [
        #
        # Try to compile using the C compiler
        #
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([$2],[])],
                       [prj_cv_attribute_$1=yes],
                       [prj_cv_attribute_$1=no])
        AS_IF([test "x$prj_cv_attribute_$1" = "xyes"], [
            AC_LANG_PUSH(C++)
            AC_COMPILE_IFELSE([AC_LANG_PROGRAM([extern "C" {
                           $2
                           }],[])],
                           [prj_cv_attribute_$1=yes],
                           [prj_cv_attribute_$1=no])
            AC_LANG_POP(C++)
        ])
    ])
    AC_MSG_CHECKING([for attribute $1])
    AC_MSG_RESULT([$prj_cv_attribute_$1])
    AS_IF([test "x$prj_cv_attribute_$1" = "xyes"], [
        AS_IF([test "x$3" = "x"],
            [AC_DEFINE_UNQUOTED([HAVE_$1], [1], [Define to 1 if attribute $1 is supported])],
            [AC_DEFINE_UNQUOTED([HAVE_$3], [1], [Define to 1 if attribute $1 is supported])]
        )
    ])
])

# Check compiler for the specified version of the C++ standard
# Usage: CHECK_COMPILER_CXX([standard], [option], [definition])
# Note:
# - [definition] can be omitted if it is equal to attribute
#
AC_DEFUN([CHECK_COMPILER_CXX], [
    case "$1" in
        11)
m4_define([_prj_cv_compiler_body_11], [[
#ifndef __cplusplus
#error This is not a C++ compiler
#elif __cplusplus < 201103L
#error This is not a C++11 compiler
#else
#include <iostream>
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    /* decltype */
    int a = 5;
    decltype(a) b = a;
    return (b - a);
}
#endif  // __cplusplus >= 201103L
]])
            ;;
        14)
m4_define([_prj_cv_compiler_body_14], [[
#ifndef __cplusplus
#error This is not a C++ compiler
#elif __cplusplus < 201402L
#error This is not a C++14 compiler
#else
#include <iostream>
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    /* Binary integer literals */
    constexpr auto i = 0b0000000000101010;
    static_assert(i == 42, "wrong value");
    return 0;
}
#endif  // __cplusplus >= 201402L
]])
            ;;
        17)
m4_define([_prj_cv_compiler_body_17], [[
#ifndef __cplusplus
#error This is not a C++ compiler
#elif __cplusplus < 201703L
#error This is not a C++17 compiler
#else
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    // Check constexpr lambda
    auto identity = [](int n) constexpr { return n; };
    static_assert(identity(123) == 123);
    return 0;
}
#endif  // __cplusplus >= 201703L
]])
            ;;
        *)
            AC_MSG_ERROR([invalid first argument as [$1] to [$0]])
            ;;
    esac
    case "$2" in
        std)
            prj_cv_option=-std=c++$1
            ;;
        gnu)
            prj_cv_option=-std=gnu++$1
            ;;
        *)
            AC_MSG_ERROR([invalid first argument as [$2] to [$0]])
            ;;
    esac

    AC_CACHE_VAL(prj_cv_compiler_cxx_[$1], [
        prj_cv_compiler_save_CXXFLAGS="$CXXFLAGS"
        CXXFLAGS="$prj_cv_option $CXXFLAGS"

        #
        # Try to compile using the C++ compiler
        #
        AC_LANG_PUSH(C++)
        AC_COMPILE_IFELSE([AC_LANG_SOURCE(_prj_cv_compiler_body_[$1])],
                       [prj_cv_compiler_cxx_$1=yes],
                       [prj_cv_compiler_cxx_$1=no])
        AC_LANG_POP(C++)

        CXXFLAGS="$prj_cv_compiler_save_CXXFLAGS"
    ])
    AC_MSG_CHECKING([for compiler c++ [$1]])
    AC_MSG_RESULT([$prj_cv_compiler_cxx_$1])
    AS_IF([test "x$prj_cv_compiler_cxx_[$1]" = "xyes"],
        [CXXFLAGS="$prj_cv_option $CXXFLAGS"],
        [AC_MSG_ERROR([A compiler with support for C++[$1] language features is required])]
    )
])


##########################
# Configure compiler capabilities
#
AC_DEFUN([COMPILER_CAPABILITY_SETUP],
[
AC_MSG_CHECKING([for compiler])

CFLAGS="-D_GNU_SOURCE -fPIC $CFLAGS"
CXXFLAGS="-D_GNU_SOURCE -fPIC $CXXFLAGS"

case $CC in
    gcc*|g++*)
        AC_MSG_RESULT([gcc])
        CFLAGS="$CFLAGS -Wall -Wextra -Werror -Wundef \
                -ffunction-sections -fdata-sections -Wsequence-point -pipe -Winit-self -Wmissing-include-dirs \
                -Wno-free-nonheap-object "
        CXXFLAGS="$CXXFLAGS -Wshadow -Wall -Wextra -Werror -Wundef \
                -ffunction-sections -fdata-sections -Wsequence-point -pipe -Winit-self -Wmissing-include-dirs \
                -Wno-free-nonheap-object "
        ;;
    icc*|icpc*)
        AC_MSG_RESULT([icc])
        CFLAGS="$CFLAGS -Wall -Werror"
        CXXFLAGS="$CXXFLAGS -Wall -Werror"
        ;;
    clang*|clang++*)
        AC_MSG_RESULT([clang])
        CFLAGS="$CFLAGS -Wall -Werror -Wno-self-assign"
        CXXFLAGS="$CXXFLAGS -Wall -Werror"
        # workaround for clang w/o -Wnon-c-typedef-for-linkage
        CXXFLAGS="$CXXFLAGS -Wno-unknown-warning-option -Wno-non-c-typedef-for-linkage"
        ;;
    *)
        AC_MSG_RESULT([unknown])
        ;;
esac

# Control debug support
#
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug],
        [Enable debug mode (default=no)]), [], [enable_debug=no])
AC_MSG_CHECKING(
    [for debug support])
if test "x$enable_debug" = xyes; then
    AC_MSG_RESULT([yes])
    CFLAGS="$CFLAGS -g -D_DEBUG"
    CXXFLAGS="$CXXFLAGS -g -D_DEBUG"
else
    AC_MSG_RESULT([no])
    CFLAGS="$CFLAGS -g -O3 -DNDEBUG"
    CXXFLAGS="$CXXFLAGS -g -O3 -DNDEBUG"
fi

# Control symbols visibility
#
AC_ARG_ENABLE([symbol_visibility],
    AS_HELP_STRING([--enable-symbol-visibility],
        [Enable symbols visibility (default=no)]), [], [enable_symbol_visibility=no])
if test "x$enable_symbol_visibility" = xno; then
    CHECK_COMPILER_ATTRIBUTE([visibility],
        [extern __attribute__((__visibility__("hidden"))) int hiddenvar;
         extern __attribute__((__visibility__("default"))) int exportedvar;
         extern __attribute__((__visibility__("hidden"))) int hiddenfunc (void);
         extern __attribute__((__visibility__("default"))) int exportedfunc (void);
         void dummyfunc (void) {}],
        [ATTRIBUTE_VISIBILITY])
    AC_MSG_CHECKING([for symbols visibility])
    AS_IF([test "x$prj_cv_attribute_visibility" = "xyes"],
        [CXXFLAGS="$CXXFLAGS -fvisibility=hidden"
         CFLAGS="$CFLAGS -fvisibility=hidden"
         AC_DEFINE_UNQUOTED([DEFINED_EXPORT_SYMBOL], [1], [Define to 1 to hide symbols])
         AC_MSG_RESULT([no])
        ],
        [
         AC_MSG_RESULT([yes])
         AC_MSG_WARN([A compiler with -fvisibility option is required for this feature])
        ]
    )
else
    AC_MSG_CHECKING([for symbols visibility])
    AC_MSG_RESULT([yes])
fi

CHECK_COMPILER_CXX([14], [std], [])
])
