AM_CFLAGS = \
	-std=gnu99 \
	-fstack-protector \
	-Wall \
	-pedantic \
	-Wstrict-prototypes \
	-Wundef \
	-fno-common \
	-Werror-implicit-function-declaration \
	-Wformat \
	-Wformat-security \
	-Werror=format-security \
	-Wconversion

bin_PROGRAMS = user-session-launch

user_session_launch_SOURCES = \
	src/launcher.c \
	src/pam.c

# FIXME: add pkgconfig checks for these instead
user_session_launch_LDADD = \
	$(SYSTEMD_LIBS) \
	-lpam \
	-lpam_misc

EXTRA_DIST = patches/dbus-fix-sba-for-dbus-activation.patch

systemdsystemunitdir = @SYSTEMDSYSTEMUNITDIR@
systemduserunitdir = @SYSTEMDUSERUNITDIR@

systemdsystemunit_DATA = \
	units/system/user-session-launch@.service \
	units/system/systemd-stop-user-sessions.service

systemduserunit_DATA = \
	units/user/dbus.socket \
	units/user/dbus.service \
	units/user/cmdline.target \
	units/user/graphical.target \
	units/user/display-server.target

if HAVE_E
systemduserunit_DATA += \
	units/user/enlightenment.service
endif

if HAVE_XBMC
systemduserunit_DATA += \
	units/user/xbmc.service
endif

if HAVE_XFCE
systemduserunit_DATA += \
	units/user/xfce4-session.service \
	units/user/xfwm4.service
endif
if HAVE_GNOME
systemduserunit_DATA += \
	units/user/gnome-session.service
endif
if HAVE_MATE
systemduserunit_DATA += \
	units/user/mate-session.service
endif
if HAVE_KDE
systemduserunit_DATA += \
	units/user/kde.service
endif
if HAVE_MYTH
systemduserunit_DATA += \
	units/user/mythfrontend.service
endif
if HAVE_OPENBOX
systemduserunit_DATA += \
	units/user/openbox.service
endif
if HAVE_STEAM
systemduserunit_DATA += \
	units/user/steam.service
endif



install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)/shutdown.target.wants
	ln -sf ../systemd-stop-user-sessions.service $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)/shutdown.target.wants/

