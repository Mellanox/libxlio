AC_PREREQ(2.64)

# Process this file with autoconf to produce a configure script.
AC_INIT([json-c], 0.17.0, [json-c@googlegroups.com])

AM_INIT_AUTOMAKE([foreign])

AC_CONFIG_MACRO_DIRS([autoconf-archive/m4])

AC_PROG_MAKE_SET
AC_CANONICAL_HOST

# Enable threading by default (as in Meson config)
AC_ARG_ENABLE(threading,
 AS_HELP_STRING([--enable-threading],
   [Enable code to support partly multi-threaded use]),
[if test x$enableval = xyes; then
  enable_threading=yes
  AC_DEFINE(ENABLE_THREADING, 1, [Enable partial threading support])
fi],
[enable_threading=yes
 AC_DEFINE(ENABLE_THREADING, 1, [Enable partial threading support])])

# Enable RDRAND by default (as in Meson config)
AC_ARG_ENABLE(rdrand,
 AS_HELP_STRING([--enable-rdrand],
   [Enable RDRAND Hardware RNG Hash Seed generation on supported x86/x64 platforms.]),
[if test x$enableval = xyes; then
  enable_rdrand=yes
  AC_DEFINE(ENABLE_RDRAND, 1, [Enable RDRAND Hardware RNG Hash Seed])
fi],
[enable_rdrand=yes
 AC_DEFINE(ENABLE_RDRAND, 1, [Enable RDRAND Hardware RNG Hash Seed])])

# enable silent build by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs
AM_PROG_CC_C_O
AC_PROG_CC_C99

# Checks for header files
AC_CONFIG_HEADER(config.h)
AC_CONFIG_HEADER(json_config.h)
AC_HEADER_STDC

# Check all headers from Meson config
AC_CHECK_HEADERS([dlfcn.h endian.h fcntl.h float.h inttypes.h limits.h locale.h memory.h stdarg.h stdint.h strings.h string.h syslog.h sys/cdefs.h sys/param.h sys/stat.h sys/types.h sys/resource.h unistd.h xlocale.h], [], [], [])

# Special handling for inttypes.h (as in original)
AC_CHECK_HEADER(inttypes.h,[AC_DEFINE([JSON_C_HAVE_INTTYPES_H],[1],[Public define for json_inttypes.h])])

# Check for STDC headers
AC_CHECK_HEADERS([stdlib.h stdarg.h string.h float.h], [], [], [])
AC_DEFINE(STDC_HEADERS, 1, [Define to 1 if you have the ANSI C header files])

# Checks for typedefs, structures, and compiler characteristics
AC_C_CONST
AC_TYPE_SIZE_T

# Check for __thread support
AC_CACHE_CHECK([for __thread support], ac_cv___thread, [dnl
AC_LINK_IFELSE([dnl
AC_LANG_PROGRAM([[#undef __thread
static __thread int a; int foo (int b) { return a + b; }]],
		[[exit (foo (0));]])],
	       ac_cv___thread=yes, ac_cv___thread=no)
])
AS_IF([test "x$ac_cv___thread" != xno],
[AC_DEFINE(HAVE___THREAD, 1, [Have __thread])
 AC_DEFINE(SPEC___THREAD, [__thread], [Specifier for __thread])]
)

# Check for atomic builtins
AC_MSG_CHECKING(for GCC atomic builtins)
AC_LINK_IFELSE(
[
 AC_LANG_SOURCE([[
   int main() {
      volatile unsigned int val = 1;
      __sync_add_and_fetch(&val, 1);
      return 0;
   }
 ]])
],
[
 AC_MSG_RESULT([yes])
 AC_DEFINE([HAVE_ATOMIC_BUILTINS],[1],[Has atomic builtins])
],
[
 AC_MSG_RESULT([no])
])

# Check for math functions and symbols
AC_CHECK_DECLS([INFINITY], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([nan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isnan], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([isinf], [], [], [[#include <math.h>]])
AC_CHECK_DECLS([_isnan], [], [], [[#include <float.h>]])
AC_CHECK_DECLS([_finite], [], [], [[#include <float.h>]])

# Check for functions
AC_CHECK_FUNCS([snprintf vasprintf vsnprintf vprintf open realloc setlocale uselocale strcasecmp strncasecmp strdup strerror vsyslog])

# Check for _doprnt
AC_CHECK_FUNCS([_doprnt])

# Check for strtoll variants (Windows compatibility)
AC_CHECK_FUNCS([strtoll _strtoi64])

# Size checks
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([size_t], [], [#include <stddef.h>])
AC_CHECK_SIZEOF([int64_t], [], [#include <stdint.h>])
AC_CHECK_SIZEOF([ssize_t], [], [#include <sys/types.h>])

# Link with math library if needed
if test "$ac_cv_have_decl_isnan" = "yes" ; then
   AC_TRY_LINK([#include <math.h>], [float f = 0.0; return isnan(f)], [], [LIBS="$LIBS -lm"])
fi

# Initialize libtool
LT_INIT

AC_CONFIG_FILES([
Makefile
json-c.pc
json-c-uninstalled.pc
])

AC_OUTPUT
