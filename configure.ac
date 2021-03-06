#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([user-session-units], [9], [auke-jan.h.kok@intel.com])
AM_INIT_AUTOMAKE([])
AC_CONFIG_FILES([Makefile])
AC_PROG_CC

# Systemd is required, obviously
PKG_CHECK_MODULES([SYSTEMD], [systemd])

SYSTEMDSYSTEMUNITDIR="`$PKG_CONFIG --variable=systemdsystemunitdir systemd`"
AC_SUBST(SYSTEMDSYSTEMUNITDIR)
SYSTEMDUSERUNITDIR="`$PKG_CONFIG --variable=systemduserunitdir systemd`"
AC_SUBST(SYSTEMDUSERUNITDIR)
SYSTEMDUTILDIR="`$PKG_CONFIG --variable=systemdutildir systemd`"
AC_SUBST(SYSTEMDUTILDIR)

PKG_CHECK_MODULES([LIBSYSTEMD], [libsystemd >= 209])

# test for xorg-launch-helper
AC_MSG_CHECKING(for xorg-launch-helper)
if test -f "$SYSTEMDUSERUNITDIR/xorg.target" ; then
  result=yes
else
  AC_MSG_WARN([xorg-launch-helper is required for most of the units])
  result=no
fi
AC_MSG_RESULT($result)

# Check for dbus daemon path for the session bus
PKG_CHECK_MODULES([DBUS], [dbus-1])
DBUSDAEMONDIR="`$PKG_CONFIG --variable=daemondir dbus-1`"
DBUSPREFIX="`$PKG_CONFIG --variable=prefix dbus-1`"
AC_SUBST(DBUSDAEMONDIR)
AC_SUBST(DBUSPREFIX)

# Should we include units for programs not on the system? (useful for packaging)
AC_ARG_ENABLE([allunits], AS_HELP_STRING([--enable-allunits], [Include units for programs which are not detected]))

if test "x$enable_allunits" = "xyes" ; then
  E_PROG="/usr/bin/enlightenment_start"
  XFWM_PROG="/usr/bin/xfwm4"
  XFCE_PROG="/usr/bin/xfce4-session"
  XBMC_PROG="/usr/bin/xbmc-standalone"
  GNOME_PROG="/usr/bin/gnome-session"
  MATE_PROG="/usr/bin/mate-session"
  KDE_PROG="/usr/bin/startkde"
  MYTH_PROG="/usr/bin/mythfrontend"
  OPENBOX_PROG="/usr/bin/openbox"
  STEAM_PROG="/usr/bin/steam"
else
  AC_CHECK_PROG([E_PROG], [enlightenment_start], [`which enlightenment_start`])
  AC_CHECK_PROG([XFWM_PROG], [xfwm4], [`which xfwm4`])
  AC_CHECK_PROG([XFCE_PROG], [xfce4-session], [`which xfce4-session`])
  AC_CHECK_PROG([XBMC_PROG], [xbmc-standalone], [`which xbmc-standalone`])
  AC_CHECK_PROG([GNOME_PROG], [gnome-session], [`which gnome-session`])
  AC_CHECK_PROG([MATE_PROG], [mate-session], [`which mate-session`])
  AC_CHECK_PROG([KDE_PROG], [startkde], [`which startkde`])
  AC_CHECK_PROG([MYTH_PROG], [mythfrontend], [`which mythfrontend`])
  AC_CHECK_PROG([OPENBOX_PROG], [openbox], [`which openbox`])
  AC_CHECK_PROG([STEAM_PROG], [steam], [`which steam`])
fi

AM_CONDITIONAL([HAVE_E], [test -n "$E_PROG"])
AM_CONDITIONAL([HAVE_XFCE], [test -n "$XFCE_PROG"])
AM_CONDITIONAL([HAVE_XBMC], [test -n "$XBMC_PROG"])
AM_CONDITIONAL([HAVE_GNOME], [test -n "$GNOME_PROG"])
AM_CONDITIONAL([HAVE_MATE], [test -n "$MATE_PROG"])
AM_CONDITIONAL([HAVE_KDE], [test -n "$KDE_PROG"])
AM_CONDITIONAL([HAVE_MYTH], [test -n "$MYTH_PROG"])
AM_CONDITIONAL([HAVE_OPENBOX], [test -n "$OPENBOX_PROG"])
AM_CONDITIONAL([HAVE_STEAM], [test -n "$STEAM_PROG"])

AC_OUTPUT([
units/system/user-session-launch@.service
units/system/systemd-stop-user-sessions.service
units/user/dbus.socket
units/user/dbus.service
units/user/cmdline.target
units/user/graphical.target
units/user/display-server.target
units/user/enlightenment.service
units/user/xbmc.service
units/user/xfce4-session.service
units/user/xfwm4.service
units/user/gnome-session.service
units/user/mate-session.service
units/user/kde.service
units/user/mythfrontend.service
units/user/openbox.service
units/user/steam.service
])
