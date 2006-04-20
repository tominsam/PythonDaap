import dbus
import avahi
import gobject
import dbus.glib

bus = dbus.SystemBus()
server = dbus.Interface(bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)

def new_service(interface, protocol, name, type, domain, flags):
    interface, protocol, name, type, domain, host, aprotocol, address, port, txt, flags = server.ResolveService(interface, protocol, name, type, domain, avahi.PROTO_UNSPEC, dbus.UInt32(0))
    print "Found service '%s' of type '%s' in domain '%s' at address '%s:%s'" % (name, type, domain, address, port)

def remove_service(interface, protocol, name, type, domain):
    print "Service '%s' of type '%s' in domain '%s' disappeared." % (name, type, domain)

stype = '_daap._tcp'
domain = 'local'
browser = dbus.Interface(bus.get_object(avahi.DBUS_NAME, server.ServiceBrowserNew(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, stype, domain, dbus.UInt32(0))), avahi.DBUS_INTERFACE_SERVICE_BROWSER)

browser.connect_to_signal('ItemNew', new_service)
browser.connect_to_signal('ItemRemove', remove_service)
gobject.MainLoop().run()
