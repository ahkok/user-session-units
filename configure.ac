#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([user-session-units], [2], [auke-jan.h.kok@intel.com])
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

# test for xorg-launch-helper
AC_MSG_CHECKING(for xorg-launch-helper)
if test -f "$SYSTEMDUSERUNITDIR/xorg.target" ; then
  result=yes
else
  AC_ERROR([xorg-launch-helper is required for most of the units])
  result=no
fi
AC_MSG_RESULT($result)

# Check for dbus daemon path for the session bus
PKG_CHECK_MODULES([DBUS], [dbus-1])

DBUSDAEMONDIR="`$PKG_CONFIG --variable=daemondir dbus-1`"
DBUSPREFIX="`$PKG_CONFIG --variable=prefix dbus-1`"
AC_SUBST(DBUSDAEMONDIR)
AC_SUBST(DBUSPREFIX)

# these are the desktops:
PKG_CHECK_MODULES([ENLIGHTENMENT], [enlightenment],
  EPREFIX="`$PKG_CONFIG --variable=exec_prefix enlightenment`"
  AC_SUBST(EPREFIX),
  true
)
AM_CONDITIONAL([HAVE_E], [test x$EPREFIX != x])

AC_MSG_CHECKING(for XBMC)
AM_CONDITIONAL([HAVE_XBMC], [test -f /usr/bin/xbmc])
AC_MSG_RESULT($HAVE_XBMC)

PKG_CHECK_MODULES([XFCE], [xfce4-session-2.0],
  XFCEPREFIX="`$PKG_CONFIG --variable=exec_prefix xfce4-session-2.0`"
  AC_SUBST(XFCEPREFIX),
  true
)
AM_CONDITIONAL([HAVE_XFCE], [test x$XFCEPREFIX != x])

PKG_CHECK_MODULES([GNOME], [gnome-desktop-2.0],
  GNOMEPREFIX="`$PKG_CONFIG --variable=exec_prefix gnome-desktop-2.0`"
  AC_SUBST(GNOMEPREFIX),
  true
)
AM_CONDITIONAL([HAVE_GNOME], [test x$GNOMEPREFIX != x])

AC_OUTPUT([
units/system/user-session@.service
units/user/dbus.socket
units/user/dbus.service
units/user/e17.target
units/user/enlightenment.service
units/user/xbmc.target
units/user/xbmc.service
units/user/xfce4-session.service
units/user/xfce4.target
units/user/xfwm4.service
units/user/gnome.target
units/user/gnome-session.service
])
