
systemdsystemunitdir = @SYSTEMDSYSTEMUNITDIR@
systemduserunitdir = @SYSTEMDUSERUNITDIR@

systemdsystemunit_DATA = \
	units/system/user-session@.service

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


install-data-hook:
if HAVE_E
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/e17.target.wants
	ln -s ../enlightenment.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/e17.target.wants/
endif
if HAVE_XBMC
	$(mkinstalldirs) $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xbmc.target.wants
	ln -s ../xbmc.service $(DESTDIR)$(SYSTEMDUSERUNITDIR)/xbmc.target.wants/
endif
