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
import argparse

import yaml

ID_PREFIX = "traffic/id"
LABEL_PREFIX = "traffic/label"

SID = 300000000

LABELS = {}
IDMAP = {}

def print_tls_sni(output, config):
    global SID

    template = """alert tls any any -> any any (msg:"%(msg)s"; tls_sni; content:"%(content)s"; flow:to_server,established; flowbits:set,%(flowbit)s; sid:%(sid)d; rev:1;)"""

    for app in config:

        flowbits = []

        if isinstance(app["flowbit"], list):
            flowbits = app["flowbit"]
        else:
            flowbits.append(app["flowbit"])

        for flowbit in flowbits:

            if flowbit.startswith(LABEL_PREFIX):
                tag = flowbit.split("/")[-1]
                if not tag in LABELS:
                    print("error: unknown tag: %s" % (tag), file=sys.stderr)
            elif flowbit.startswith(ID_PREFIX):
                name = flowbit.split("/")[-1]
                if not name in IDMAP:
                    print("error: unknown id: %s" % (name), file=sys.stderr)
            else:
                print(
                    "warning: unknown flowbit prefix: %s" % (flowbit),
                    file=sys.stderr)

            for pattern in app["patterns"]:
                print(template % {
                    "msg": "APPID TLS SNI Pattern for %s" % (flowbit),
                    "content": pattern,
                    "flowbit": flowbit,
                    "sid": SID,
                }, file=output)
                SID += 1

def print_http_user_agent(output, config):
    global SID

    template = """alert http any any -> any any (msg:"%(msg)s"; content:"%(content)s"; http_user_agent; flow:to_server,established; flowbits:set,%(flowbit)s; sid:%(sid)d; rev:1;)"""

    for app in config:
        for pattern in app["patterns"]:
            print(template % {
                "msg": "APPID HTTP USER AGENT for %s" % (app["flowbit"]),
                "content": pattern,
                "flowbit": app["flowbit"],
                "sid": SID,
            }, file=output)
        SID += 1

def generate_rules(args):
    if args.output:
        output = open(args.output, "w")
    else:
        output = sys.stdout

    # Print out the license.
    with open("LICENSE.template") as fileobj:
        lines = fileobj.readlines()
        lines = ["# %s" % line for line in lines]
        print("".join(lines), file=output)

    for dirpath, dirnames, filenames in os.walk("."):
        for filename in filenames:
            if filename.endswith(".yaml"):
                path = os.path.join(dirpath, filename)
                with open(path) as fileobj:
                    config = yaml.load(fileobj)
                    if "labels" in config:
                        LABELS.update(config["labels"])
                    if "id-map" in config:
                        IDMAP.update(config["id-map"])
                    for key in config:
                        if key == "tls-sni-patterns":
                            print_tls_sni(output, config[key])
                        elif key == "http-user-agent-patterns":
                            print_http_user_agent(output, config[key])

def load_configs():
    configs = []
    for dirpath, dirnames, filenames in os.walk("."):
        for filename in filenames:
            if filename.endswith(".yaml"):
                path = os.path.join(dirpath, filename)
                configs.append(yaml.load(open(path)))
    return configs

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--output", metavar="<filename>",
                        help="Output filename for rules")
    parser.add_argument("command", metavar="<command>",
                        help="Command to run")
    args = parser.parse_args()

    if args.command in ["gen", "generate"]:
        generate_rules(args)
    elif args.command == "list-labels":
        labels = set()
        configs = load_configs()
        for config in configs:
            for key in config:
                if key == "tls-sni-patterns":
                    for label in config[key]:
                        for flowbit in label["flowbit"]:
                            if flowbit.startswith(LABEL_PREFIX):
                                labels.add(flowbit)
        for label in labels:
            print(label)
    elif args.command == "list-ids":
        names = set()
        configs = load_configs()
        for config in configs:
            for key in config:
                if key == "tls-sni-patterns":
                    for label in config[key]:
                        for flowbit in label["flowbit"]:
                            if flowbit.startswith(ID_PREFIX):
                                names.add(flowbit)
        for name in names:
            print(name)

if __name__ == "__main__":
    sys.exit(main())
