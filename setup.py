#!/usr/bin/env python
# Send notification to another XMPP client.
# Koen Bollen <meneer koenbollen nl>
# 2010 GPL

from distutils.core import setup
import xmppnotify

setup(
        name = "xmpp-notify",
        version = xmppnotify.APPLICATION_VERSION,
        py_modules = [ "xmppnotify" ],
        description = "Send notification to another XMPP client.",

        author = "Koen Bollen",
        author_email = "meneer@koenbollen.nl",
        url = "http://github.com/koenbollen/xmpp-notify",

        scripts = [
            "scripts/xmpp-notify-server",
            "scripts/xmpp-notify-client" ],
        data_files = [ ('/etc', ['xmpp-notify.cfg'] ) ],

    )

# vim: expandtab shiftwidth=4 softtabstop=4 textwidth=79:

