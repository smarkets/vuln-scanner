#!/usr/bin/env python3

import datetime
import json
import logging
import os
import secrets
import subprocess
import sys
import time

import boto3
from random import shuffle
from xml.etree import ElementTree

log = logging.getLogger(__name__)

WHITELIST_NAMES = {
    'Traceroute',
}
WHITELIST_PORTS = {
    'general/icmp',
    'general/CPE-T',
}


def omp_command_from_xml(xml_cmd):
    return ['/usr/bin/omp', '-i', '--xml', xml_cmd]


class VulnerabilityScanRunner(object):
    run_id = None
    current_report = None
    aws_session = None
    s3_client = None
    bucket_name = None
    bucket_prefix = None

    def __init__(self):
        self.silence_boto_logging()
        self.run_id = secrets.token_hex(6)
        self.current_report = {}
        self.setup_s3()

    # Fix from https://github.com/boto/boto3/issues/521
    # Without this the boto library will dump _every single action_ to
    # logs at DEBUG level. We don't want that.
    # NB. this only shows up once logging module is used
    def silence_boto_logging(self):
        for name in logging.Logger.manager.loggerDict.keys():
            if ('boto' in name) or ('urllib3' in name) or ('s3transfer 'in name):
                logging.getLogger(name).setLevel(logging.WARNING)

    def setup_s3(self):
        # Check that bucket config is at least sane
        self.bucket_name = os.environ.get('REPORT_UPLOAD_BUCKET')
        self.bucket_prefix = os.environ.get('REPORT_NAME_PREFIX')
        if self.bucket_name is None:
            log.info('Bucket unspecified, please set REPORT_UPLOAD_BUCKET')
            sys.exit(2)
        # This is not an error, but it is probably unwanted
        if self.bucket_prefix is None:
            log.info('Report prefix unspecified, using "scans/"')
            self.bucket_prefix = 'scans'

        try:
            self.aws_session = boto3.Session()
            self.s3_client = self.aws_session.resource('s3')
        # We do not want to blow up, uploading is optional
        except boto3.ResourceNotExistsError as err:
            log.info('Invalid resource: %s', err)
            self.aws_session = None
            self.s3_client = None

    def find_tasks(self):
        cmd = omp_command_from_xml('<get_tasks/>')
        out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
        xml_tree = ElementTree.fromstring(out.stdout.decode('utf-8'))
        nodes = xml_tree.findall('task')
        res = []
        for node in nodes:
            for name, uuid in node.items():
                log.info('Found task (%s): %s', name, uuid)
                res.append(uuid)
        return res

    def do_scan(self, task_id):
        log.info('Starting task run: %s', task_id)
        cmd = omp_command_from_xml('<start_task task_id="%s"/>' % task_id)
        subprocess.check_call(cmd)  # Yup, ignore output

    # Setting details=1 makes the query VERY expensive, skip here
    def wait_until_complete(self, task_id):
        cmd = omp_command_from_xml('<get_tasks details="0" task_id="%s"/>' % task_id)
        out = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        xml_tree = ElementTree.fromstring(out.stdout.decode('utf-8'))
        nodes = xml_tree.findall('task')
        for task_elem in nodes:
            task_status = task_elem.find('status')
            if task_status.text != 'Done':
                time.sleep(13)
                return False
        return True

    def get_report_uuid(self, task_id):
        cmd = omp_command_from_xml('<get_tasks details="1" task_id="%s"/>' % task_id)
        out = subprocess.check_output(cmd)
        xml_tree = ElementTree.fromstring(out.decode('utf-8'))
        task_node = xml_tree.find('task')
        task_status = task_node.find('status')
        if task_status.text != 'Done':
            # At least leave a trace for now
            log.info('Scan task "%s" is in inconsistent state!', task_id)

        report_nodes = task_node.find('reports').getchildren()
        # We know this is a list with just one element
        for report in report_nodes:
            void_, report_uuid = report.items()[0]
        return report_uuid

    def save_report_xml(self, report_id):
        now = datetime.datetime.now().isoformat(timespec='seconds')
        cmd = omp_command_from_xml('<get_reports report_id="%s"/>' % report_id)
        out_path = '/tmp/%s--%s--scan-results.xml' % (now, self.run_id)
        log.info('Saving report to %s', out_path)
        with open(out_path, 'w') as outfile:
            subprocess.call(cmd, stdout=outfile)
        return out_path

    def save_report_json(self, report_path):
        parsed = ElementTree.parse(report_path)
        xml_tree = parsed.getroot()
        report_root = xml_tree.find('report/report')
        self._pre_aggreted_values(report_root)

        ports = report_root.find('ports')
        self._report_ports(ports)

        results = report_root.find('results')
        self._report_results(results)

        json_path = report_path.replace('.xml', '.json')
        with open(json_path, 'w') as outfile:
            outfile.write(json.dumps(self.current_report, indent=4))
        log.info('JSON report written to: %s', json_path)
        self._upload_to_s3(json_path)

    def _upload_to_s3(self, path):
        if self.s3_client is None:
            return
        bucket = self.s3_client.Bucket(self.bucket_name)
        s3_path = os.path.join(self.bucket_prefix, os.path.basename(path))
        log.info('Uploading to: %s', s3_path)
        bucket.upload_file(path, s3_path)

    def _pre_aggreted_values(self, tree):
        vulns = tree.find('vulns')
        apps = tree.find('apps')
        #
        self.current_report['total_vulnerabilities'] = vulns.find('count').text
        self.current_report['apps_found'] = apps.find('count').text

    def _report_ports(self, ports):
        ports_on_hosts = {}
        for port in ports.findall('port'):
            name = port.text.strip()
            host = port.find('host').text
            if name in WHITELIST_PORTS:
                continue
            if name not in ports_on_hosts:
                ports_on_hosts[name] = set()
            ports_on_hosts[name].add(host)
        self.current_report['ports_found'] = sorted(list(ports_on_hosts))

    def _report_results(self, results):
        vulnerabilities = {}
        for result in results.findall('result'):
            name = result.find('name').text.strip()
            port = result.find('port').text.strip()
            host = result.find('host').text.strip()
            descr = result.find('description').text     # May be None
            threat_lvl = result.find('threat').text.strip()
            severity = result.find('severity').text.strip()
            nvt = result.find('nvt/name').text.strip()

            # Drop all useless findings. These are not vulnerabilities.
            if name in WHITELIST_NAMES:
                continue
            if port in WHITELIST_PORTS:
                continue

            if host not in vulnerabilities:
                vulnerabilities[host] = []
            vulnerabilities[host].append({
                'port': port,
                'name': name,
                'description': descr,
                'threat_level': threat_lvl,
                'severity_score': severity,
                'nvt': nvt,
            })
        self.current_report['vulnerabilities'] = vulnerabilities

    def run(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format='[%(levelname)s] %(message)s',
        )
        tasks = self.find_tasks()
        shuffle(tasks)
        for task in tasks:
            done = False
            failures = 0
            self.do_scan(task)
            while not done:
                try:
                    done = self.wait_until_complete(task)
                except subprocess.CalledProcessError as err:
                    log.info('OMP error: {}'.format(err.stderr.decode('utf-8')))
                    failures += 1
                    time.sleep(13)  # Same delay as between checks
                    # omp can fail for some time after a scan
                    if failures % 3 == 0:
                        log.info('OMP is still failing... (run %d)', failures)
                    # If we have kept failing for ~1.25h, assume we got stuck
                    if failures > 350:
                        log.info('The scan looks to have failed. Wait for resurrection.')
                        sys.exit(1)
            log.info('Scan task "%s" OK [OMP croaks: %d]', task, failures)
            #
            report_uuid = self.get_report_uuid(task)
            xml_report_path = self.save_report_xml(report_uuid)
            self.save_report_json(xml_report_path)
            self.current_report = {}


if __name__ == '__main__':
    scan = VulnerabilityScanRunner()
    scan.run()
