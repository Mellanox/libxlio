AM_CFLAGS = -Wno-error -Wno-unused-parameter -Wno-unused-function -D_GNU_SOURCE

SUBDIRS = .

noinst_LTLIBRARIES = libjson-c.la

# Headers (public) - from Meson config
noinst_HEADERS = \
	arraylist.h \
	debug.h \
	json.h \
	json_c_version.h \
	json_inttypes.h \
	json_object.h \
	json_object_iterator.h \
	json_pointer.h \
	json_tokener.h \
	json_types.h \
	json_util.h \
	json_visit.h \
	linkhash.h \
	printbuf.h \
	json_patch.h \
	json_object_private.h \
	json_pointer_private.h \
	math_compat.h \
	strdup_compat.h \
	snprintf_compat.h \
	vasprintf_compat.h \
	random_seed.h \
	strerror_override.h

# Sources (from Meson config)
libjson_c_la_SOURCES = \
	arraylist.c \
	debug.c \
	json_c_version.c \
	json_object.c \
	json_object_iterator.c \
	json_pointer.c \
	json_tokener.c \
	json_util.c \
	json_visit.c \
	linkhash.c \
	printbuf.c \
	random_seed.c \
	strerror_override.c

libjson_c_la_LDFLAGS = -no-undefined

# Clean files
DISTCLEANFILES = \
	config.h \
	json-c-uninstalled.pc \
	json-c.pc \
	json_config.h

distclean-local:
	-rm -rf $(testsubdir)

