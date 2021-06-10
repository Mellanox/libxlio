# compiler.m4 - Configure compiler capabilities
#
# Copyright (C) Mellanox Technologies Ltd. 2001-2021.  ALL RIGHTS RESERVED.
# See file LICENSE for terms.
#


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
        CXXFLAGS="$CXXFLAGS -Wall -Werror -Wno-overloaded-virtual"
        ;;
    *)
        AC_MSG_RESULT([unknown])
        ;;
esac

# Control debug support
#
AC_ARG_ENABLE([debug],
    AC_HELP_STRING([--enable-debug],
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

])
