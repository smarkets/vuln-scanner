#!/usr/bin/env python3

"""
This script reads a JSON report, as produced by the vulnerability
scanner.

The output is a JSON document, either printed to stdout or written to
a specified file. The output is not meant to directly be readable by
humans, but intended to be displayed with a dashboard.
"""

import argparse
import json

class VulnerabilityHighlighter(object):
    opts = None
    report = None
    vuln_report = None

    def __init__(self) -> None:
        self.report = {}
        self._parse_args()

    def _parse_args(self) -> None:
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--input',
            help='Path to vulnerability scan JSON report',
            action='store', dest='input_json', required=True)
        parser.add_argument('-o', '--output',
            help='Path where to write the results (leave out for stdin)',
            action='store', dest='out_path', required=False)
        self.opts = parser.parse_args()

    def read_json(self) -> None:
        with open(self.opts.input_json, 'r') as infile:
            self.vuln_report = json.load(infile)

    def process_data(self) -> None:
        self.report = {
            'High': {},
            'Medium': {},
            'Low': {},
        }
        for node_ip, vulns in self.vuln_report['vulnerabilities'].items():
            for vuln in vulns:
                nvt_id      = vuln['nvt']
                level       = vuln['threat_level']
                score       = vuln['severity_score']
                vuln_name   = vuln['name']
                vuln_descr  = vuln['description']

                # We can ignore all "log only" stuff for now
                if level not in ('High', 'Medium', 'Low'):
                    continue

                if nvt_id not in self.report[level]:
                    self.report[level][nvt_id] = {
                        'score': score,
                        'name': vuln_name,
                        'description': vuln_descr,
                        'found_on': {},
                    }
                # We're working around the fact that set is not a JSON
                # serialisable type. Dictionary is. Deduplication is king.
                self.report[level][nvt_id]['found_on'][node_ip] = ''

    def write_results(self) -> None:
        if self.opts.out_path:
            with open(self.opts.out_path, 'w') as out:
                json.dump(self.report, out, indent=4)
        else:
            print('%s' % json.dumps(self.report, indent=4))


    def run(self) -> None:
        self.read_json()
        self.process_data()
        self.write_results()

if __name__ == '__main__':
    vuln_highlighter = VulnerabilityHighlighter()
    vuln_highlighter.run()
