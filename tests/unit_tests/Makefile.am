noinst_PROGRAMS = unit_tests

# google test shows some warnings that are suppressed
AM_CXXFLAGS = \
	-Wno-error=sign-compare \
	-Wno-error=missing-field-initializers \
	-g -O3 -std=c++14

AM_CPPFLAGS = \
	-DGTEST_LANG_CXX11=1 \
	-DGTEST_HAS_PTHREAD=1 \
	-DGTEST_USE_OWN_TR1_TUPLE=0 \
	-DGTEST_HAS_TR1_TUPLE=0 \
	-DGTEST_ENV_HAS_STD_TUPLE_=1 \
	-DGTEST_USES_SIMPLE_RE=0 \
	-DGTEST_HAS_COMBINE=0 \
	-DPTHREADS \
	\
	-DGTEST_DONT_DEFINE_ASSERT_GT=0 \
	-DGTEST_DONT_DEFINE_ASSERT_GE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_LT=0 \
	-DGTEST_DONT_DEFINE_ASSERT_LE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_NE=0 \
	-DGTEST_DONT_DEFINE_ASSERT_EQ=0 \
	-DGTEST_DONT_DEFINE_SUCCEED=0 \
	-DGTEST_DONT_DEFINE_FAIL=0 \
	-DGTEST_DONT_DEFINE_TEST=0 \
	\
	-DGTEST_HAS_STD_WSTRING=0 \
	-DGTEST_HAS_GLOBAL_STRING=0 \
	\
	-DGTEST_OS_WINDOWS=0 \
	-DGTEST_OS_LINUX_ANDROID=0 \
	-DGTEST_OS_CYGWIN=0 \
	-DGTEST_OS_SOLARIS=0 \
	-DGTEST_OS_SYMBIAN=0 \
	-DGTEST_OS_WINDOWS_MOBILE=0 \
	-DGTEST_OS_QNX=0 \
	-DGTEST_OS_MAC=0 \
	-DGTEST_OS_IOS=0 \
	-DGTEST_OS_ZOS



# lgtest
noinst_LTLIBRARIES = libgtest.la

libgtest_la_CPPFLAGS = \
	-I$(top_srcdir)/tests/gtest/googletest \
	-I$(top_srcdir)/tests/gtest/googletest/include \
	$(AM_CPPFLAGS)

libgtest_la_LDFLAGS = -pthread -static
libgtest_la_CXXFLAGS = \
	$(AM_CXXFLAGS)

EXTRA_DIST = \
	$(top_srcdir)/tests/gtest/googletest/include \
	$(top_srcdir)/tests/gtest/googletest/src \
	$(top_srcdir)/tests/gtest/googletest/README.md \
	$(top_srcdir)/tests/gtest/googletest/LICENSE

libgtest_la_SOURCES = \
	$(top_srcdir)/tests/gtest/googletest/src/gtest-all.cc \
	$(top_srcdir)/tests/gtest/googletest/src/gtest_main.cc

# unit_tests
unit_tests_LDADD = libgtest.la $(LIBJSON_LIBS)

unit_tests_CPPFLAGS = \
	-I$(top_srcdir)/ \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/config \
    -I$(top_srcdir)/src/core/util \
	-I$(top_srcdir)/tests/gtest \
	-I$(top_srcdir)/tests/gtest/googletest/include \
	$(AM_CPPFLAGS) \
	$(LIBJSON_CFLAGS)

unit_tests_LDFLAGS = -no-install
unit_tests_CXXFLAGS = \
	$(AM_CXXFLAGS)

# Tests
unit_tests_SOURCES = \
	main.cpp \
    config/config_registry.cpp \
	config/config_descriptor.cpp \
	config/inline_loader.cpp \
	config/json_loader.cpp \
	config/json_descriptor_provider.cpp \
	config/parameter_descriptor.cpp \
	config/schema_analyzer.cpp \
    $(top_builddir)/src/core/config/loaders/inline_loader.cpp \
	$(top_builddir)/src/core/config/loaders/json_loader.cpp \
	$(top_builddir)/src/core/config/descriptor_providers/json_descriptor_provider.cpp \
	$(top_builddir)/src/core/config/descriptor_providers/schema_analyzer.cpp \
	$(top_builddir)/src/core/config/descriptors/parameter_descriptor.cpp \
	$(top_builddir)/src/core/config/descriptors/config_descriptor.cpp \
	$(top_builddir)/src/core/config/config_registry.cpp \
	$(top_builddir)/src/core/config/config_strings.cpp \
	$(top_builddir)/src/core/config/json_object_handle.cpp \
	$(top_builddir)/src/core/config/json_utils.cpp


unit_tests_DEPENDENCIES = \
	libgtest.la

