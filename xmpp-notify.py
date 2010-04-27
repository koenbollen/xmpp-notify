#!/usr/bin/env python
# Send notification to another XMPP client.
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL
#

import os
import sys
import ctypes
import xmpp
import socket
import threading
import time
import Queue
from ConfigParser import ConfigParser, NoOptionError, NoSectionError
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

VERSION = "0.0"

def _shred( string ):
    f = "finding offset"
    header = ctypes.string_at( id(f), sys.getsizeof(f) ).find(f)
    location = id(string) + header
    size = sys.getsizeof(string) - header
    #print "Clearing 0x%08x size %i bytes" % (location, size)
    ctypes.memset( location, 0, size )


class XMPPNotify( ThreadingMixIn, HTTPServer ):

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

    timeout = 10
    allow_reuse_address= True
    queue_size = -1
    daemon_threads = True

    def __init__(self, autostart=False ):
        self.__config = None
        self.__password = None

        if not self.__configuration():
            raise Exception, "Unable to read config"

        general = self.config['general']
        addr = ( general['bind'], general['listen'] )
        HTTPServer.__init__(self, addr, NotifyRequestHandler )

        self.__queue = Queue.Queue(self.queue_size)
        self.__queue_thread = None

        self.__client = None
        self.__connected = False
        self.__alive = False

        if autostart:
            self.start()


    def __configuration(self ):

        cfg = ConfigParser()
        cfg.read( self.filelist_config )

        if cfg.has_section( "xmpp-notify" ):
            cfg.add_section( "general" )
            for k,v in cfg.items("xmpp-notify"):
                cfg.set( "general", k, v )
            cfg.remove_section( "xmpp-notify" )

        fields = [
                ("target",   "general", True,  cfg.get,        None    ),
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
                    # TODO: Change message
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
                parent = os.path.dirname( file )
                if os.access(file, os.W_OK) or os.access(parent, os.W_OK):
                    res['general']['logfile'] = file
                    break

        # TODO: check of logfile is 0600

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


    def __queue_handle(self ):
        while self.__queue.qsize() > 0 or self.__alive:
            try:
                msg = self.__queue.get( True, 1 )
            except Queue.Empty:
                continue
            try:
                #client.send( xmpp.Message( "koen@koenbollen.nl", "AppTest" ) )
                self.log_message( "sent: %s" % msg[:10] )
            finally:
                self.__queue.task_done()


    @property
    def config(self ):
        return self.__config

    @property
    def queue(self ):
        return self.__queue


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
        self.__connected = True
        return True


    def start(self ):
        if self.__alive:
            return False
        if not self.__connected:
            if not self.connect():
                return False
        self.__alive = True
        thr = threading.Thread(name="Thread-Queue", target=self.__queue_handle)
        thr.daemon = True
        thr.start()
        self.__queue_thread = thr
        self.serve_forever()
        return True


    def close(self ):
        self.__alive = False
        self.socket.shutdown(socket.SHUT_RD)
        self.__queue.join()
        self.__queue_thread.join(1)
        self.socket.close()


    def log_message(self, format, *args):
        general = self.config['general']
        msg = "[%s] %s" % (time.asctime(), format%args )
        if general['log'] == "syslog":
            pass # TODO: Implement syslog..
        else:
            try:
                fp = open( general['logfile'], "ab" )
            except (OSError, IOError), e:
                print >>sys.stderr, "error:", e
            try:
                fp.write( "%s\n" % msg )
            except (OSError, IOError), e:
                print >>sys.stderr, "error:", e
            finally:
                fp.close()



class NotifyRequestHandler( BaseHTTPRequestHandler ):
    server_version = "XMPPNotify/"+VERSION
    protocol_version = "HTTP/1.1"

    def do_GET(self ):
        pass

    def do_POST(self ):

        # TODO: Parse postdata and construct msg.
        msg = self.path

        try:
            self.server.queue.put_nowait( msg )
        except Queue.Full:
            return self.send_error( 503 )

        self.send_response( 202, "Message Queued" )
        self.end_headers()

    def log_message(self, format, *args):
        msg = "%s %s" % ( self.address_string(), format%args )
        self.server.log_message( msg )



def main():
    try:
        server = XMPPNotify()
    except:
        return
    try:
        server.start()
    except KeyboardInterrupt:
        server.close()

if __name__ == "__main__":
    main()

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:

