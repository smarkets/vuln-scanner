#!/usr/bin/env python3

import ipaddress
import json
import subprocess
import sys
from typing import Generator, NamedTuple
from xml.etree import ElementTree

TARGET_TEMPLATE = \
"""<create_target>
    <name>{name}</name>
    <hosts>{expanded_cidr}</hosts>
    <exclude_hosts>{blacklist_string}</exclude_hosts>
    <port_range>{port_list}</port_range>
</create_target>
"""

# We probably never need this but let's keep it around for now
TARGET_TEMPLATE_NO_RANGE = """
<create_target>
    <name>{name}</name>
    <hosts>{expanded_cidr}</hosts>
    <exclude_hosts>{blacklist_string}</exclude_hosts>
</create_target>
"""


def omp_command_from_xml(xml_cmd):
    return ['/usr/bin/omp', '-i', '--xml', xml_cmd]


# NOTE: this is needed to work around a really confusing (and highly
# irritating) bug. Sometime between 2018-09 and 2019-01 the behaviour of
# libopenvas_base::openvas_hosts_new_with_max() changed. As far as I
# see, the packages have not been changed.
# However, before the string '10.100.1.0/24' was valid and got expanded
# correctly. With the latest situation, the string is NO LONGER VALID,
# and returns parsing errors. So instead of the library expanding CIDR
# subnets for us, it has started to come back with "not a valid address,
# no hosts for you!"
# After having spent 3 days debugging the root cause, I give up.
#
# To work around this weird misbehaviour, we now manually expand the
# subnet, because a comma-separated list of addresses (without CIDR
# netmasks) functions as intended. Unbelievable.
def expand_cidr(cidr):
    subnet = ipaddress.IPv4Network(cidr)
    hosts = [str(host) for host in subnet.hosts()]
    return ','.join(hosts)


class Target(NamedTuple):
    name: str
    cidr: str
    port_list: str
    blacklist: list

    def to_xml_string(self) -> str:
        blacklist_string = ','.join(self.blacklist)
        if self.port_list:
            return TARGET_TEMPLATE.format(
                name=self.name, expanded_cidr=expand_cidr(self.cidr),
                port_list=self.port_list, blacklist_string=blacklist_string,
            )
        else:
            return TARGET_TEMPLATE_NO_RANGE.format(
                name=self.name, expanded_cidr=expanded_cidr(self.cidr),
                blacklist_string=blacklist_string,
            )


def config_targets(filename: str) -> Generator[Target, None, None]:
    with open(filename) as config:
        document = json.load(config)
    for target in document['targets']:
        ports = ''
        target_ports_name = target.get('port_list', '')
        if target_ports_name:
            ports = document[target_ports_name]
        yield Target(
            target['name'],
            target['cidr'],
            ports,
            target.get('blacklist', []),
        )


def run():
    for target in config_targets(sys.argv[1]):
        tgt = target.to_xml_string()
        cmd = omp_command_from_xml(tgt)
        out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response = ElementTree.fromstring(out.stdout.decode('utf-8'))
        if int(response.attrib['status']) >= 400:
            print('Received response:\n{xml_out}'.format(xml_out=out.stdout), flush=True)
            raise Exception(response.attrib['status_text'])


if __name__ == '__main__':
    run()
