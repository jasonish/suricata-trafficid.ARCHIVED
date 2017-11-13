#! /usr/bin/env python3
#
# Copyright (C) 2017 Open Information Security Foundation
#
# You can copy, redistribute or modify this Program under the terms of
# the GNU General Public License version 2 as published by the Free
# Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

"""This tools accepts Suricata appid definitions in YAML format and
outputs the appid rule set.

It is not intended for end-users of appid, instead end-users should
grab the generated .rules files.

"""

import sys
import os

import yaml

SID = 300000000

def print_tls_sni(config):
    global SID

    template = """alert tls any any -> any any (msg:"%(msg)s"; tls_sni; content:"%(content)s"; flow:to_server,established; flowbits:set,%(flowbit)s; sid:%(sid)d; rev:1;)"""

    for app in config:
        for pattern in app["patterns"]:
            print(template % {
                "msg": "APPID TLS SNI Pattern for %s" % (app["flowbit"]),
                "content": pattern,
                "flowbit": app["flowbit"],
                "sid": SID,
            })
            SID += 1

def print_http_user_agent(config):
    global SID

    template = """alert http any any -> any any (msg:"%(msg)s"; content:"%(content)s"; http_user_agent; flow:to_server,established; flowbits:set,%(flowbit)s; sid:%(sid)d; rev:1;)"""

    for app in config:
        for pattern in app["patterns"]:
            print(template % {
                "msg": "APPID HTTP USER AGENT for %s" % (app["flowbit"]),
                "content": pattern,
                "flowbit": app["flowbit"],
                "sid": SID,
            })
        SID += 1

def main():

    # Print out the license.
    with open("LICENSE.template") as fileobj:
        lines = fileobj.readlines()
        lines = ["# %s" % line for line in lines]
        print("".join(lines))

    for dirpath, dirnames, filenames in os.walk("."):
        for filename in filenames:
            if filename.endswith(".yaml"):
                path = os.path.join(dirpath, filename)
                with open(path) as fileobj:
                    config = yaml.load(fileobj)
                    for key in config:
                        if key == "tls-sni-patterns":
                            print_tls_sni(config[key])
                        elif key == "http-user-agent-patterns":
                            print_http_user_agent(config[key])
                        else:
                            raise Exception("Unknown appid type: %s" % (key))

if __name__ == "__main__":
    sys.exit(main())
