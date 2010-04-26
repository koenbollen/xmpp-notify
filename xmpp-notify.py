#!/usr/bin/env python
# Send notification to another XMPP client.
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL
#

import os
import sys
import ctypes
import xmpp
from ConfigParser import ConfigParser, NoOptionError, NoSectionError


def _shred( string ):
    f = "finding offset"
    header = ctypes.string_at( id(f), sys.getsizeof(f) ).find(f)
    location = id(string) + header
    size = sys.getsizeof(string) - header
    print "Clearing 0x%08x size %i bytes" % (location, size)
    ctypes.memset( location, 0, size )


class XMPPNotify( object ):

    filelist_config = (
            "xmpp-notity.cfg",
            os.path.expanduser( "~/.xmpp-notify.cfg" ),
            "/etc/xmpp-notify.cfg",
        )

    filelist_log = (
            "/var/log/xmpp-notify.log",
            os.path.expanduser( "~/.xmpp-notify.log" ),
            "xmpp-notify.log",
            "/tmp/xmpp-notify-%s.log" % os.getlogin(),
        )


    def __init__(self, autoconnect=True ):
        self.__config = None
        self.__password = None

        if not self.__configuration():
            return

        self.__client = None

        if autoconnect:
            self.connect()


    def __configuration(self ):

        cfg = ConfigParser()
        cfg.read( self.filelist_config )

        # TODO: check of logfile is 0600

        if cfg.has_section( "xmpp-notify" ):
            cfg.add_section( "general" )
            for k,v in cfg.items("xmpp-notify"):
                cfg.set( "general", k, v )
            cfg.remove_section( "xmpp-notify" )

        fields = [
                ("debug",    "general", False, cfg.getboolean, False   ),
                ("listen",   "general", False, cfg.getint,     5222    ),
                ("bind",     "general", False, cfg.get,        ""      ),
                ("log",      "general", False, cfg.get,        "file"  ),
                ("logfile",  "general", False, cfg.get,        None    ),
                ("domain",   "auth",    True,  cfg.get,        False   ),
                ("username", "auth",    True,  cfg.get,        False   ),
                ("password", "auth",    True,  cfg.get,        False   ),
                ("resource", "auth",    False, cfg.get,        "notify"),
                ("host",     "server",  False, cfg.get,        None    ),
                ("port",     "server",  False, cfg.getint,     5222    ),
            ]

        res = {}
        for f, s, r, g, d in fields:
            try:
                value = g( s, f )
                if g == cfg.get and len(value) < 1:
                    raise NoOptionError(s,f)
            except (NoSectionError, NoOptionError):
                if r:
                    print >>sys.stderr, "missing configuration: %s" % f
                    return False
                value = d
            if s not in res:
                res[s] = {}
            res[s][f] = value

        general = res['general']
        if general['log'] not in ("file", "syslog"):
            print >>sys.stderr, "invalid configuation: log = file | syslog"
            return False
        if general['log'] == "syslog":
            # TODO: syslog
            res['general']['logfile'] = None
        if general['log'] == "file" and general['logfile'] == None:
            for file in self.filelist_log:
                print "test file:", file
                parent = os.path.dirname( file )
                if os.access(file, os.W_OK) or os.access(parent, os.W_OK):
                    res['general']['logfile'] = file
                    break

        if general['debug']:
            print "Configuration:"
            for section in sorted(res.keys()):
                for field in sorted(res[section].keys()):
                    value = res[section][field]
                    if field == "password":
                        value = "*****"
                    print " %s.%s = %r" % (section,field,value)
            print

        self.__config = res
        return True


    @property
    def config(self ):
        return self.__config


    def connect(self ):
        general = self.config['general']
        auth = self.config['auth']
        server = self.config['server']
        client = xmpp.Client( auth['domain'], debug=[] )
        if "host" not in server or not server['host']:
            server['host'] = auth['domain']
        client.connect( server=(server['host'], server['port']) )
        client.auth(
                auth['username'],
                auth['password'],
                auth['resource']
            )
        _shred( self.__config['auth']['password'] )
        self.__client = client
        return True


def main():
    server = XMPPNotify( autoconnect=False )
    #client.send( xmpp.Message( "koen@koenbollen.nl", "AppTest" ) )

if __name__ == "__main__":
    main()

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:

