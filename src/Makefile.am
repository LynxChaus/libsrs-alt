AM_CFLAGS =
EXTRA_DIST = address.h hash.h srs_alt.h timestamp.h
include_HEADERS = srs_alt.h

LDADD = ../lib/libcompat.a

lib_LIBRARIES = libsrs_alt.a
libsrs_alt_a_SOURCES = address.c hash.c srs_alt.c timestamp.c
libsrs_alt_a_CFLAGS = $(AM_CFLAGS)
libsrs_alt_a_LIBADD = ../lib/libcompat.a

lib_LTLIBRARIES = libsrs_alt.la
libsrs_alt_la_LDFLAGS = -version-info 1:0
libsrs_alt_la_SOURCES = address.c hash.c srs_alt.c timestamp.c
libsrs_alt_la_CFLAGS = $(AM_CFLAGS)
libsrs_alt_la_LIBADD = ../lib/libcompat.la