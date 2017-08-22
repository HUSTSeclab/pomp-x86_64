#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([reverse_from_coredump], [0.0.1], [mudongliangabcd@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([disasm], [x86_init], [], [AC_MSG_ERROR([unable to find the x86_init() function])])
AC_CHECK_LIB([elf], [gelf_getehdr], [], [AC_MSG_ERROR([unable to find the gelf_getehdr() function])])
AC_CHECK_LIB([z3], [Z3_algebraic_is_value], [], [AC_MSG_ERROR([unable to find the Z3_algebraic_is_value() function])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h malloc.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strerror])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
