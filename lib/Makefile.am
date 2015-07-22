EXTRA_DIST = hmac.h sha1.h

noinst_LIBRARIES = libcompat.a
libcompat_a_SOURCES = hmac.c sha1.c
libcompat_a_CFLAGS = $(AM_CFLAGS)
libcompat_a_LIBADD = $(LIBOBJS) $(ALLOCA)

noinst_LTLIBRARIES = libcompat.la
libcompat_la_SOURCES = hmac.c sha1.c
libcompat_la_CFLAGS = $(AM_CFLAGS)
libcompat_la_LIBADD = $(LTLIBOBJS) $(ALLOCA)
