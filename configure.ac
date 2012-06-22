#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([user-session-units], [1], [auke-jan.h.kok@intel.com])
AM_INIT_AUTOMAKE([])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
PKG_CHECK_MODULES([SYSTEMD], [systemd])

SYSTEMDSYSTEMUNITDIR="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
AC_SUBST(SYSTEMDSYSTEMUNITDIR)
SYSTEMDUSERUNITDIR="`$PKG_CONFIG --variable=systemduserunitdir systemd`"
AC_SUBST(SYSTEMDUSERUNITDIR)

AC_OUTPUT
