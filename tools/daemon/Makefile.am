sbin_PROGRAMS = xliod

xliod_LDADD =

xliod_CPPFLAGS = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core

xliod_LDFLAGS  = 
xliod_CFLAGS = 

xliod_SOURCES = \
	daemon.c \
	loop.c \
	hash.c \
	store.c \
	flow.c \
	message.c \
	notify.c \
	nl.c \
	tc.c

noinst_HEADERS = \
	daemon.h \
	hash.h \
	bitmap.h \
	nl.h \
	tc.h
