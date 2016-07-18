#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT([fcgiwrap], [1.1.0], [root@localdomain.pl])
AM_CFLAGS="-std=gnu99 -Wall -Wextra -Werror -pedantic"
if test x"$CFLAGS" = x""; then
    AM_CFLAGS="$AM_CFLAGS -O2 -g3"
else
    AM_CFLAGS="$AM_CFLAGS $CFLAGS"
fi

AC_SUBST([AM_CFLAGS])

# Checks for programs.
AC_PROG_CC
PKG_PROG_PKG_CONFIG

# Create the config.h.
AC_CONFIG_HEADERS([config.h])

# Checks for libraries.
AC_CHECK_LIB([fcgi], [FCGX_Init],, [AC_MSG_ERROR([FastCGI library is missing])])

# systemd support.
AC_ARG_WITH([systemd],
  AS_HELP_STRING([--with-systemd], [support systemd socket activation]),
  [], [with_systemd=check])
have_systemd=no
if test "x$with_systemd" != "xno"; then
  PKG_CHECK_MODULES(systemd, [libsystemd],
    [AC_DEFINE(HAVE_SYSTEMD, 1, [Define if systemd is available])
    have_systemd=yes],
  have_systemd=no)
  if test "x$have_systemd" = xno -a "x$with_systemd" = xyes; then
    AC_MSG_ERROR([systemd support requested but libraries not found])
  fi
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test "x$have_systemd" = "xyes"])

AC_ARG_WITH([systemdsystemunitdir],
        AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
        [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != xno -a "x$have_systemd" != xno; then
        AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h],, [AC_MSG_ERROR([fcntl.h header missing])])
AC_CHECK_HEADERS([limits.h stdlib.h string.h unistd.h],, [AC_MSG_ERROR([at least one important system header file is missing])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strchr strdup strrchr])
AC_CHECK_FUNCS([dup2 putenv select setenv strerror],, [AC_MSG_ERROR([seems as if your libraries don't provide an expected function])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
