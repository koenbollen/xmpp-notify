#!/usr/bin/env python
# Send notification to another XMPP client.
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL
#

import os
import sys
import ctypes
import re
import socket
import threading
import time
import urllib
import Queue

try:
    from syslog import *
    HAVE_SYSLOG=True
except ImportError:
    HAVE_SYSLOG=False

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from ConfigParser import ConfigParser, NoOptionError, NoSectionError
from SocketServer import ThreadingMixIn

try:
    import warnings
    warnings.simplefilter( 'ignore', DeprecationWarning )
    import xmpp
except ImportError:
    print >>sys.stderr, "missing module: xmpp!!"
    print >>sys.stderr, "http://xmpppy.sourceforge.net/"
    print >>sys.stderr, "aptitude install python-xmpp"
    sys.exit(1)


SERVER_VERSION = "0.0"
PROTOCOL_VERSION = 0

__all__ = [ "XMPPNotify" ]

def _shred( string ):
    """Find memory of a string and override it."""
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

    loglevels = {
            'emergency': LOG_EMERG,
            'alert':     LOG_ALERT,
            'critical':  LOG_CRIT,
            'error':     LOG_ERR,
            'warning':   LOG_WARNING,
            'notice':    LOG_NOTICE,
            'info':      LOG_INFO,
            'debug':     LOG_DEBUG
        }

    timeout = 10
    allow_reuse_address= True
    queue_size = -1
    daemon_threads = True

    def __init__(self, configfile=None, verbose=False, autostart=False ):
        self.verbose = verbose
        self.__config = None
        self.__password = None

        if not self.__configuration(configfile):
            print >>sys.stderr, "error: unable to read configuration"
            sys.exit(0)

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


    def __configuration(self, configfile ):

        cfg = ConfigParser()
        if configfile:
            cfg.read( self.filelist_config+(configfile,) )
        else:
            cfg.read( self.filelist_config )

        if cfg.has_section( "xmpp-notify" ):
            cfg.add_section( "general" )
            for k,v in cfg.items("xmpp-notify"):
                cfg.set( "general", k, v )
            cfg.remove_section( "xmpp-notify" )

        fields = [
                ("target",   "general", True,  cfg.get,        None    ),
                ("listen",   "general", False, cfg.getint,     5222    ),
                ("bind",     "general", False, cfg.get,        ""      ),
                ("log",      "general", False, cfg.get,        "file"  ),
                ("logfile",  "general", False, cfg.get,        None    ),
                ("loglevel", "general", False, cfg.get,        "error" ),
                ("domain",   "auth",    True,  cfg.get,        False   ),
                ("username", "auth",    True,  cfg.get,        False   ),
                ("password", "auth",    True,  cfg.get,        False   ),
                ("resource", "auth",    False, cfg.get,        "notify"),
                ("host",     "server",  False, cfg.get,        None    ),
                ("port",     "server",  False, cfg.getint,     5222    ),
            ]

        res = {}
        for field, sect, req, func, default in fields:
            try:
                try:
                    value = func( sect, field )
                except ValueError:
                    print >>sys.stderr, "invalid configuration: %s" % field
                    return False
                if func == cfg.get and len(value) < 1:
                    raise NoOptionError(sect,field)
            except (NoSectionError, NoOptionError):
                if req:
                    print >>sys.stderr, "missing configuration: %s" % field
                    return False
                value = default
            if sect not in res:
                res[sect] = {}
            res[sect][field] = value

        general = res['general']
        res['general']['loglevel'] = self.loglevels.get(
                general['loglevel'],
                LOG_ERR
            )
        if general['log'] not in ("file", "syslog"):
            print >>sys.stderr, "invalid configuation: log = file | syslog"
            return False
        if general['log'] == "syslog":
            if not HAVE_SYSLOG:
                print >>sys.stderr, "error: syslog not supported"
                return False
            openlog( "xmpp-notify" )
            setlogmask( LOG_UPTO(general['loglevel']) )
            res['general']['logfile'] = None
        if general['log'] == "file" and general['logfile'] == None:
            for file in self.filelist_log:
                parent = os.path.dirname( file )
                if os.access(file, os.W_OK) or os.access(parent, os.W_OK):
                    res['general']['logfile'] = file
                    break

        # TODO: check of logfile is 0600

        if general['loglevel'] >= LOG_DEBUG:
            print "Configuration:"
            for section in sorted(res.keys()):
                for field in sorted(res[section].keys()):
                    value = res[section][field]
                    if field == "password":
                        value = "*****"
                    print " %s.%s = %r" % (section,field,value)
            print

        self.__config = res
        self.log_message( "configuration read", LOG_DEBUG )
        return True


    def __queue_handle(self ):
        while self.__queue.qsize() > 0 or self.__alive:
            try:
                info = self.__queue.get( True, 1 )
            except Queue.Empty:
                continue
            try:
                msg = xmpp.Message( info['target'], info['data'],
                        subject=info['subject'] )
                ret = self.__client.send( msg )
                if ret:
                    self.log_message( "sent %s to %s (%s)" % (
                            info['subject'], info['target'], ret
                        ), LOG_INFO )
                else:
                    self.log_message( "failed to send %s to %s! (%s)" % (
                            info['subject'], info['target'], ret
                        ), LOG_WARNING )
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
        ret = client.connect( server=(server['host'], server['port']) )
        if not ret:
            self.log_message( "error: could not connect!", LOG_CRIT )
            return False
        self.log_message( "connected with: %s" % ret, LOG_INFO )

        ret = client.auth(
                auth['username'],
                auth['password'],
                auth['resource']
            )
        if not ret:
            self.log_message( "error: could not authenticate!", LOG_CRIT )
            return False
        self.log_message( "authenticated using: %s" % ret, LOG_INFO )

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
        self.log_message( "service started (pid:%d)" % os.getpid(), LOG_INFO )
        self.serve_forever()
        return True


    def close(self ):
        self.log_message( "shutting down...", LOG_INFO )
        self.__alive = False
        closelog()
        self.socket.shutdown(socket.SHUT_RD)
        self.__queue.join()
        self.__queue_thread.join(1)
        self.socket.close()


    def log_message(self, msg, loglevel=LOG_INFO):
        general = self.config['general']
        if self.verbose:
            print msg
        if loglevel > general['loglevel']:
            return
        if general['log'] == "syslog":
            syslog( loglevel, msg )
        else:
            msg = "[%s] %s" % (time.asctime(), msg)
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
    server_version = "XMPPNotify/"+SERVER_VERSION
    protocol_version = "HTTP/1.1"

    fields = {
            # name:    type,  required
            'target':  (str,  False ),
            'subject': (str,  False ),
            'data':    (str,  True  ),
        }

    rx_path = re.compile( r"/(\d+)/notify(?:/(\w+))?" )

    def do_POST(self ):
        general = self.server.config['general']

        result = self.rx_path.match( self.path )
        if not result:
            return self.send_error( 404 )
        version, subject = result.groups()
        if int(version) != PROTOCOL_VERSION:
            return self.send_error( 400 )
        if not subject:
            subject = "Notification"

        try:
            length = min( int( self.headers['Content-Length'] ), 4096 )
        except (ValueError, KeyError):
            length = 4096

        try:
            rawdata = self.rfile.read( length )
        except IOError, e:
            return self.send_error( 500 )

        msg = { 'target': general['target'],
                'subject': subject }
        for pair in rawdata.split("&"):
            try:
                key, value = pair.split( "=", 1 )
            except ValueError:
                key, value = pair, True
            key = key.lower().strip()
            if key not in self.fields:
                continue
            msg[key] = urllib.unquote( value.strip().replace("+"," ") )
        for key, (func, req) in self.fields.items():
            try:
                value = func( msg[key] )
                msg[key] = value
            except (KeyError, ValueError):
                if req: return self.send_error( 400 )

        try:
            self.server.queue.put_nowait( msg )
        except Queue.Full:
            return self.send_error( 503 )

        try:
            self.send_response( 202, "Message Queued" )
            self.send_header( "Content-Length:", 0 )
            self.end_headers()
        except IOError, e:
            self.server.log_message( "unable to send reply: %s"%e, LOG_WARNING )


    def log_message(self, format, *args):
        msg = "%s %s" % ( self.address_string(), format%args )
        self.server.log_message( msg, LOG_INFO )



def main():
    server = XMPPNotify(verbose=True)
    try:
        server.start()
    except KeyboardInterrupt:
        server.close()
    return 0

if __name__ == "__main__":
    sys.exit( main() )

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:

