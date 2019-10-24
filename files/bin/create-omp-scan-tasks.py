#!/usr/bin/env python3

import argparse
import logging
import os
import subprocess

from xml.etree import ElementTree

log = logging.getLogger(__name__)

TASK_TEMPLATE = """
<create_task>
    <name>{task_name}</name>
    <config id="{config_uuid}"/>
    <target id="{target_uuid}"/>
    <preferences>
        <preference>
            <scanner_name>max_hosts</scanner_name>
            <value>{cpu_cores}</value>
        </preference>
        <preference>
            <scanner_name>max_checks</scanner_name>
            <value>3</value>
        </preference>
    </preferences>
</create_task>
"""

SCAN_TASKS = {
    'discover': 'Discovery',
    'simple': 'Full and fast',
    'dangerous': 'Full and fast ultimate',
    'slow': 'Full and very deep',
    'very-dangerous': 'Full and very deep ultimate',
}

def process_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--scan-key',
        help='OpenVAS scan type',
        dest='scan_key', default='simple',
        choices=sorted(list(SCAN_TASKS.keys())),
    )
    parser.add_argument('-v', '--verbose',
        dest='verbose', action='store_true',
        default=False,
    )
    return parser.parse_args()

def get_cpu_core_count():
    return len(os.sched_getaffinity(0))

def omp_get_targets():
    cmd = ['/usr/bin/omp', '-i', '--xml', '<get_targets/>']
    out = subprocess.check_output(cmd)
    xml_tree = ElementTree.fromstring(out.decode('utf-8'))
    nodes = xml_tree.findall('target')
    res = []
    for node in nodes:
        for name, uuid in node.items():
            log.info('Adding target: %s', uuid)
            res.append(uuid)
    return res

# The configurations are the scan names. But because everything in
# OpenVAS is internally addressed via UUIDs, we need to resolve those.
# The provided scan types are a subset of those available, but the
# plain discovery versions are not really useful. So we keep the
# accepted options listed in argument choices and simply disallow access
# to the remaining ones.
def omp_get_configs():
    cmd = ['/usr/bin/omp', '-i', '--xml', '<get_configs/>']
    out = subprocess.check_output(cmd)
    xml_tree = ElementTree.fromstring(out.decode('utf-8'))
    nodes = xml_tree.findall('config')
    res = {}
    for config_node in nodes:
        name_ = config_node.find('name')
        void_, uuid = config_node.items()[0]
        log.info('Adding config: "%s" => %s', name_.text, uuid)
        res[name_.text] = uuid
    return res

# 'targets' is a list of UUID strings
# 'configs' is a dictionary of readable names mapped to UUID strings
#
# ```
# omp --xml='
#           <create_task>
#             <name>...</name>
#             <config id="$uuid">...</config>
#             <target id="$uuid">...</target>
#           </create_task>'
def assign_scans(targets, configs, scan_key):
    log.info('Creating task for scan: "%s"' % scan_key)
    num_cpus = get_cpu_core_count()
    scan_config_id = configs[scan_key]
    for target_id in targets:
        task_xml = TASK_TEMPLATE.format(
            task_name=scan_key,
            config_uuid=scan_config_id,
            target_uuid = target_id,
            cpu_cores=num_cpus,
        )
        cmd = ['/usr/bin/omp', '--xml=%s' % task_xml]
        log.info('Running:\n%r', cmd)
        subprocess.check_output(cmd)


def run():
    args = process_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format='[%(levelname)s] %(message)s',
    )
    scan_type = SCAN_TASKS[args.scan_key]

    configs = omp_get_configs()
    targets = omp_get_targets()
    assign_scans(targets, configs, scan_type)


if __name__ == '__main__':
    run()
