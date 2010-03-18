#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.63)
AC_INIT(fcgiwrap, 1.0, root@localdomain.pl)
AM_CFLAGS="-std=gnu99 -Wall -Wextra -Werror -pedantic"
if test x"$CFLAGS" = x""; then
    AM_CFLAGS="$AM_CFLAGS -O2 -g3"
else
    AM_CFLAGS="$AM_CFLAGS $CFLAGS"
fi

AC_SUBST([AM_CFLAGS])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([fcgi], [FCGX_Init])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([dup2 putenv select setenv strchr strdup strerror strrchr])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
