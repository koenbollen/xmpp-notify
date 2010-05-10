#
# Send notification to another XMPP client.
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL
#

import os
import sys
import stat
import ctypes
import re
import socket
import threading
import time
import urllib
import shlex
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


APPLICATION_VERSION = "0.1"
PROTOCOL_VERSION = 1

__all__ = [ "XMPPNotify" ]

def _getlogin():
    try:
        return os.getlogin()
    except OSError:
        pass
    for e in ('LOGNAME','USER','USERNAME'):
        try:
            return os.environ[e]
        except KeyError:
            pass
    try:
        import pwd
        return pwd.getpwuid(os.getuid())[0]
    except (KeyError, IndexError):
        raise OSError, "unable to find login"

def _shred( string ):
    """Find memory of a string and override it."""
    f = "finding offset"
    header = ctypes.string_at( id(f), sys.getsizeof(f) ).find(f)
    location = id(string) + header
    size = sys.getsizeof(string) - header
    #print "Clearing 0x%08x size %i bytes" % (location, size)
    ctypes.memset( location, 0, size )

def _multipart( rawdata, boundary ):
    parts = rawdata.split( "--"+boundary )
    if parts[-1].strip() != "--":
        raise ValueError, "invalid sentinel"
    for part in parts[1:-1]:
        headers = {}
        data = None
        for line in part.lstrip().splitlines():
            if len( line.strip() ) < 1: # end of headers
                data = []
            elif data is None: # still reading headers
                key, value = line.split( ":", 1 )
                headers[key.strip().lower()] = value.strip()
            else:
                data.append( line )
        try:
            dispos = headers['content-disposition'].split(";")
            if dispos[0].strip() != "form-data":
                continue
            name = None
            for attr in dispos[1:]:
                key, value = shlex.split( attr.replace("=", " ") )
                if key.strip() == "name":
                    name = value.strip()
                    break
            if not name:
                raise ValueError, "missing name=field"
        except KeyError:
            raise ValueError, "missing Content-Disposition header"
        yield name, "\n".join(data)


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
            "/tmp/xmpp-notify-%s.log" % _getlogin(),
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
    queue_size = 25
    daemon_threads = True

    def __init__(self, conffile=None, verbose=False, fork=False, start=False ):
        self.verbose = verbose
        self.fork = fork
        self.pidfile = None
        self.__config = None
        self.__password = None

        if not self.__configuration(conffile):
            print >>sys.stderr, "error: unable to read configuration"
            sys.exit(1)

        general = self.config['general']
        addr = ( general['bind'], general['listen'] )
        HTTPServer.__init__(self, addr, NotifyRequestHandler )

        self.__queue = Queue.Queue(self.queue_size)
        self.__queue_thread = None

        self.__client = None
        self.__connected = False
        self.__alive = False

        if start:
            self.start()


    def __configuration(self, configfile ):
        """Read, parse and validate configuration files."""

        # Create configparser and read file(s):
        cfg = ConfigParser()
        if configfile:
            fileread = cfg.read( self.filelist_config+(configfile,) )
        else:
            fileread = cfg.read( self.filelist_config )

        # Sort sections:
        if cfg.has_section( "xmpp-notify" ):
            cfg.add_section( "general" )
            for k,v in cfg.items("xmpp-notify"):
                cfg.set( "general", k, v )
            cfg.remove_section( "xmpp-notify" )

        # Available fields, these will be read:
        fields = [
                # field       section   required,  type,        default
                ("target",   "general", True,      cfg.get,     None    ),
                ("key",      "general", False,     cfg.get,     None    ),
                ("listen",   "general", False,     cfg.getint,  5222    ),
                ("bind",     "general", False,     cfg.get,     ""      ),
                ("log",      "general", False,     cfg.get,     "file"  ),
                ("logfile",  "general", False,     cfg.get,     None    ),
                ("loglevel", "general", False,     cfg.get,     "error" ),
                ("domain",   "auth",    True,      cfg.get,     False   ),
                ("username", "auth",    True,      cfg.get,     False   ),
                ("password", "auth",    True,      cfg.get,     False   ),
                ("resource", "auth",    False,     cfg.get,     "notify"),
                ("host",     "server",  False,     cfg.get,     None    ),
                ("port",     "server",  False,     cfg.getint,  5222    ),
            ]


        # Get and parse fields:
        res = {}
        for field, sect, req, func, default in fields:
            try:
                try:
                    value = func( sect, field )
                except ValueError:
                    t = "string"
                    if func == cfg.getint:
                        t = "integer"
                    msg = "error: invalid configuration value: %s" \
                          " (should be: %d)" % (field, t)
                    print >>sys.stderr, msg
                    return False
                if func == cfg.get and len(value) < 1:
                    raise NoOptionError(sect,field)
            except (NoSectionError, NoOptionError):
                if req:
                    msg = "error: missing configuration field: %s"%field
                    print >>sys.stderr, msg
                    return False
                value = default
            if sect not in res:
                res[sect] = {}
            res[sect][field] = value

        # Act of certain config options like logging:
        general = res['general']
        res['general']['loglevel'] = self.loglevels.get(
                general['loglevel'],
                LOG_ERR
            )
        if general['log'] not in ("file", "syslog"):
            msg = "error: invalid configuation value: log = file | syslog"
            print >>sys.stderr, msg
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

        self.__config = res

        # Check whether the configfile(s) are readable to others:
        if sys.platform != "win32":
            for file in fileread:
                try:
                    stats = os.stat( file )
                    mode = stat.S_IMODE( stats[stat.ST_MODE] )
                except OSError:
                    continue
                if (mode & 0077) != 0:
                    self.log_message(
                            "warning: config %s can be read by others!"%file,
                            LOG_WARNING
                        )


        # Log configuration if loglevel is debug:
        if general['loglevel'] >= LOG_DEBUG and self.verbose:
            print "Configuration:"
            for section in sorted(res.keys()):
                for field in sorted(res[section].keys()):
                    value = res[section][field]
                    if field == "password":
                        value = "*****"
                    print " %s.%s = %r" % (section,field,value)
            print


        self.log_message(
                "configuration read: %s" % (repr(fileread)),
                LOG_DEBUG )
        return True


    def __queue_handle(self ):
        """Wait for messages from the queue and handle them."""

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
        """Connect and authenticate the the xmpp server.

        Tries to shred the password from memory.
        """
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

        # Whould set visible to contacts:
        #client.sendInitPresence( requestRoster=0 )

        try:
            _shred( self.__config['auth']['password'] )
        except Exception, e:
            self.log_message(
                    "unable to shred password from memory! %s" % (str(e)),
                    LOG_WARNING
                )
        self.__client = client
        self.__connected = True
        return True


    def start(self ):
        """Connect, start thread(s) and serve forever."""

        if self.__alive:
            return False
        self.daemonize()
        if self.pidfile:
            fp = open( self.pidfile, "wb" )
            print >>fp, "%d" % os.getpid()
            fp.close()
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
        """Shutdown, close connections and clear the queue."""

        self.log_message( "shutting down...", LOG_INFO )
        self.__alive = False
        closelog()
        self.socket.shutdown(socket.SHUT_RD)

        if self.__queue_thread and self.__queue_thread.isAlive():
            self.__queue.join()
            self.__queue_thread.join(1)

        self.socket.close()

        if self.pidfile:
            try:
                os.unlink( self.pidfile )
            except (OSError, IOError):
                pass


    def log_message(self, msg, loglevel=LOG_INFO):
        """Log a message to a file or syslog."""

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


    def daemonize(self ):
        if not self.fork:
            return
        self.log_message( "Detaching process to the background", LOG_DEBUG )
        self.verbose = False
        try:
            pid = os.fork()
        except OSError, e:
            raise Exception, "%s [%d]" % (e.strerror, e.errno)
        if pid:
            os._exit(0)

        os.setsid()

        import signal
        signal.signal( signal.SIGHUP, signal.SIG_IGN )

        try:
            pid = os.fork()
        except OSError, e:
            raise Exception, "%s [%d]" % (e.strerror, e.errno)
        if pid:
            os._exit(0)

        os.chdir( "/" )
        os.umask( 0 )

        fd = os.open( os.devnull, os.O_RDWR )
        os.close(0)
        os.dup2( fd, 0 )
        os.close(1)
        os.dup2( fd, 1 )
        os.close(2)
        os.dup2( fd, 2 )
        os.close( fd )



class NotifyRequestHandler( BaseHTTPRequestHandler ):
    server_version = "XMPPNotify/"+APPLICATION_VERSION
    protocol_version = "HTTP/1.1"

    fields = {
            # name:    type,  required
            'target':  (str,  False ),
            'key':     (str,  False ),
            'subject': (str,  False ),
            'data':    (str,  True  ),
        }

    rx_path = re.compile( r"/(\d+)/notify(?:/(\w+))?" )

    def do_POST(self ):
        general = self.server.config['general']

        # Parse /path and verify version:
        result = self.rx_path.match( self.path )
        if not result:
            return self.send_error( 404 )
        version, subject = result.groups()
        if int(version) != PROTOCOL_VERSION:
            return self.send_error( 400 )
        if not subject:
            subject = "Notification"

        # Read contenttype and validate:
        try:
            ctype = self.headers['Content-Type'].strip().lower()
            parts = ctype.split( ";" )
            ctype = parts[0].strip()
            ctype_params = {}
            for part in parts[1:]:
                if not "=" in part:
                    continue
                k, v = part.strip().split("=",1)
                ctype_params[k.strip()] = v.strip()
            if ctype not in (
                    "application/x-www-form-urlencoded",
                    "multipart/form-data", "text/plain" ):
                raise ValueError, "invalid contenttype"
        except (KeyError, ValueError):
            return self.send_error( 400 )

        # Get content-length and max at 4096:
        try:
            length = min( int( self.headers['Content-Length'] ), 4096 )
        except (ValueError, KeyError):
            length = 4096

        # Read bytes:
        try:
            rawdata = self.rfile.read( length )
        except IOError, e:
            return self.send_error( 500 )

        # Parse rawdata for key=value fields:
        msg = { 'target': general['target'],
                'subject': subject }
        if ctype == "application/x-www-form-urlencoded":
            for pair in rawdata.split("&"):
                try:
                    key, value = pair.split( "=", 1 )
                except ValueError:
                    key, value = pair, True
                key = key.lower().strip()
                if key not in self.fields:
                    continue
                msg[key] = urllib.unquote( value.strip().replace("+"," ") )
        elif ctype == "multipart/form-data":
            try:
                boundary = ctype_params['boundary']
            except KeyError:
                return self.send_error( 400 )
            try:
                for key, value in _multipart( rawdata, boundary ):
                    msg[key] = value
            except ValueError:
                return self.send_error( 400 )
        elif ctype == "text/plain":
            msg['data'] = rawdata.strip()

        # Convert values and check required fields:
        for key, (func, req) in self.fields.items():
            try:
                value = func( msg[key] )
                msg[key] = value
            except (KeyError, ValueError):
                if req: return self.send_error( 400 )

        # Check the key if required:
        if general['key'] is not None:
            if "key" not in msg:
                return self.send_error( 401 )
            if msg['key'] != general['key']:
                return self.send_error( 403 )

        # Queue the new request:
        try:
            self.server.queue.put_nowait( msg )
        except Queue.Full:
            return self.send_error( 503 )

        # And reply:
        try:
            self.send_response( 202, "Message Queued" )
            self.send_header( "Content-Length:", 0 )
            self.end_headers()
        except IOError, e:
            self.server.log_message( "unable to send reply: %s"%e, LOG_WARNING )


    def log_message(self, format, *args):
        msg = "%s %s" % ( self.address_string(), format%args )
        self.server.log_message( msg, LOG_INFO )


# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:

