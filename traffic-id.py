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

def print_err(msg):
    print(msg, file=sys.stderr)

def as_list(_id):
    if isinstance(_id, type([])):
        return _id
    return [_id]

def print_tls_sni(args, output, config):
    global SID

    template = """alert tls any any -> any %(dport)s (msg:"%(msg)s"; tls_sni; content:"%(content)s"; isdataat:!1,relative; flow:to_server,established; %(flowbits)s; %(noalert)ssid:%(sid)d; rev:1;)"""

    for tls in config:

        if not "id" in tls:
            raise Exception("Missing id: %s" % (str(tls)))

        msg = "SURICATA TRAFFIC-ID: %s" % (",".join(as_list(tls["id"])))

        flowbits = []

        for _id in as_list(tls["id"]):
            flowbits.append("flowbits: set,%s/%s" % (ID_PREFIX, _id))

        if "labels" in tls:
            for label in as_list(tls["labels"]):
                flowbits.append("flowbits:set,%s/%s" % (LABEL_PREFIX, label))

        if not args.disable_noalert:
            noalert = "noalert; "
        else:
            noalert = ""

        if "ports" in tls:
            ports = "[%s]" % (",".join([str(p) for p in tls["ports"]]))
        else:
            ports = "any"

        for pattern in tls["patterns"]:
            print(template % {
                "msg": msg,
                "content": pattern,
                "flowbits": "; ".join(flowbits),
                "sid": SID,
                "noalert": noalert,
                "dport": ports,
            }, file=output)

            SID += 1

def print_rules(args, output, config):
    global SID

    for rule in config:
        proto = rule["proto"]

        options = []

        if "msg" in rule:
            options += ["msg:\"SURICATA TRAFFIC-ID: %s\"" % (rule["msg"])]
        else:
            options += ["msg:\"SURICATA TRAFFIC-ID: %s\"" % as_list(rule["id"])]

        if "http_host" in rule:
            options += [
                "content:\"%s\"" % (rule["http_host"]),
                "http_host",
            ]

        if "http_user_agent" in rule:
            options += [
                "content:\"%s\"" % (rule["http_user_agent"]),
                "http_user_agent",
            ]

        options.append("flow:to_server,established")

        for _id in as_list(rule["id"]):
            options.append("flowbits:set,%s/%s" % (ID_PREFIX, _id))

        for label in as_list(rule["labels"]):
            options.append("flowbits:set,%s/%s" % (LABEL_PREFIX, label))

        if not args.disable_noalert:
            options.append("noalert")

        options += ["sid:%d" % (SID), "rev:1"]

        print("alert %s any any -> any any (%s;)" % (
            proto, "; ".join(options)), file=output)

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
                    config = yaml.load(fileobj, Loader=yaml.Loader)
                    if "labels" in config:
                        LABELS.update(config["labels"])
                    if "id-map" in config:
                        IDMAP.update(config["id-map"])
                    for key in config:
                        if key == "tls-sni-patterns":
                            print_tls_sni(args, output, config[key])
                        elif key == "rules":
                            print_rules(args, output, config[key])

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
    parser.add_argument("--disable-noalert", action="store_true", default=False)
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
