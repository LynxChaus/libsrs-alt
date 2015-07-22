#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([libsrs_alt],[1.0],[srs@mirtol.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([srs.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_LIBOBJ_DIR([lib])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_PROG_RANLIB

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([malloc.h stdlib.h string.h sys/socket.h sys/timeb.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STRNLEN
AC_CHECK_LIB(socket, bind)
AC_CHECK_FUNCS([ftime memset socket strchr strdup strncasecmp])
AC_TYPE_SIZE_T

AC_ARG_WITH(base64compat, [  --with-base64compat     Turn on non-standard BASE64 encoding (MTA compatibility mode)],
		[AC_DEFINE([SRS_BASE64COMPAT], [], [Turn on non-standard BASE64 encoding])] )

AC_CONFIG_FILES([lib/Makefile]
                [src/Makefile]
		[Makefile])
AC_OUTPUT
