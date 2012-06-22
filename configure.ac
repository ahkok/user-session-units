#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([user-session-units], [1], [auke-jan.h.kok@intel.com])
AM_INIT_AUTOMAKE([])
AC_CONFIG_FILES([Makefile])

# Systemd is required, obviously
PKG_CHECK_MODULES([SYSTEMD], [systemd])

SYSTEMDSYSTEMUNITDIR="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
AC_SUBST(SYSTEMDSYSTEMUNITDIR)
SYSTEMDUSERUNITDIR="`$PKG_CONFIG --variable=systemduserunitdir systemd`"
AC_SUBST(SYSTEMDUSERUNITDIR)
SYSTEMDUTILDIR="`$PKG_CONFIG --variable=systemdutildir systemd`"
AC_SUBST(SYSTEMDUTILDIR)

# Check for dbus daemon path for the session bus
PKG_CHECK_MODULES([DBUS], [dbus-1])

DBUSDAEMONDIR="`$PKG_CONFIG --variable=daemondir dbus-1`"
DBUSPREFIX="`$PKG_CONFIG --variable=prefix dbus-1`"
AC_SUBST(DBUSDAEMONDIR)
AC_SUBST(DBUSPREFIX)

AC_OUTPUT([
units/system/user-session@.service
units/user/dbus.socket
units/user/dbus.service
])
