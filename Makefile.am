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
	-lsystemd-login \
	-lpam \
	-lpam_misc

EXTRA_DIST = patches/dbus-fix-sba-for-dbus-activation.patch

systemdsystemunitdir = @SYSTEMDSYSTEMUNITDIR@
systemduserunitdir = @SYSTEMDUSERUNITDIR@

systemdsystemunit_DATA = \
	units/system/user-session-launch@.service \
	units/system/user-session@.service \
	units/system/systemd-stop-user-sessions.service

systemduserunit_DATA = \
	units/user/dbus.socket \
	units/user/dbus.service

if HAVE_E
systemduserunit_DATA += \
	units/user/e17.target \
	units/user/enlightenment.service
endif

if HAVE_XBMC
systemduserunit_DATA += \
	units/user/xbmc.target \
	units/user/xbmc.service
endif

if HAVE_XFCE
systemduserunit_DATA += \
	units/user/xfce4-session.service \
	units/user/xfwm4.service \
	units/user/xfce4.target
endif
if HAVE_GNOME
systemduserunit_DATA += \
	units/user/gnome.target \
	units/user/gnome-session.service
endif
if HAVE_KDE
systemduserunit_DATA += \
	units/user/kde.target \
	units/user/startkde.service
endif
if HAVE_MYTH
systemduserunit_DATA += \
	units/user/mythtv.target \
	units/user/mythfrontend.service
endif
if HAVE_OPENBOX
systemduserunit_DATA += \
	units/user/openbox.target \
	units/user/openbox.service
endif
if HAVE_STEAM
systemduserunit_DATA += \
	units/user/steam.target \
	units/user/steam.service
endif



install-data-hook:
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)/shutdown.target.wants
	ln -sf ../systemd-stop-user-sessions.service $(DESTDIR)$(SYSTEMDSYSTEMUNITDIR)/shutdown.target.wants/
if HAVE_E
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/e17.target.wants
	ln -sf ../enlightenment.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/e17.target.wants/
endif
if HAVE_XBMC
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xbmc.target.wants
	ln -sf ../xbmc.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xbmc.target.wants/
endif
if HAVE_XFCE
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xfce4.target.wants
	ln -sf ../xfce4-session.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xfce4.target.wants/
	ln -sf ../xfwm4.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xfce4.target.wants/
endif
if HAVE_GNOME
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/gnome.target.wants
	ln -sf ../gnome-session.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/gnome.target.wants/
endif
if HAVE_KDE
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/kde.target.wants
	ln -sf ../startkde.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/kde.target.wants/
endif
if HAVE_MYTH
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/mythtv.target.wants
	ln -sf ../mythfrontend.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/mythtv.target.wants/
endif
if HAVE_OPENBOX
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/openbox.target.wants
	ln -sf ../openbox.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/openbox.target.wants/
endif
if HAVE_STEAM
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/steam.target.wants
	ln -sf ../steam.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/steam.target.wants/
endif

