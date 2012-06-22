
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

