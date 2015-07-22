SUBDIRS = lib src .
EXTRA_DIST = MTAs

LDADD = lib/libcompat.a

bin_PROGRAMS = srs
noinst_PROGRAMS = test

test_SOURCES = test.c
test_LDFLAGS = src/.libs/libsrs_alt.a

srs_SOURCES = srs.c
srs_LDFLAGS = src/.libs/libsrs_alt.a
