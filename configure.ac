AC_INIT(cexxy, 0.1-dev)

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([aux-bin])

AM_INIT_AUTOMAKE([1.11 foreign subdir-objects])

AM_SILENT_RULES([yes])

AC_PROG_CXX
AX_CXX_COMPILE_STDCXX(11)

LT_INIT

dnl ***************************************************************************
dnl Check for dependencies
dnl ***************************************************************************

dnl Check for GMP
AC_CHECK_LIB(gmp, __gmpz_init, ,
       [AC_MSG_ERROR([GNU MP not found, see https://gmplib.org/])])


DX_INIT_DOXYGEN(cexxy, [Doxyfile], [doxygen])

AC_OUTPUT([
Makefile
doc/Makefile
src/Makefile
tests/Makefile
])
