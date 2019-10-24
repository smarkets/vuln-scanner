#!/bin/bash

set -eu

# Remove any previous state
rm -f /var/lib/openvas/mgr/tasks*

# Remove any leftover scan result files
# (docker restart = same container, all files in place)
rm -f /etc/*.xml /etc/*.json

# Launch redis
if [ ! -d /var/run/redis-openvas ]; then
    mkdir -p /var/run/redis-openvas
fi
/usr/bin/redis-server /etc/redis/redis-openvas.conf

# OpenVAS
/usr/sbin/openvassd                                 # scanning daemon
/usr/sbin/openvasmd --listen=127.0.0.1 --port 9390 --schedule-timeout=0  # management daemon
sync; sync; sync

# Make 'omp' work as early as possible
/usr/local/sbin/setup-openvas-users.sh

# With the `--foreground` flag, this process blocks until ready
sleep 2
/usr/sbin/openvasmd --rebuild --foreground

sync; sync; sync

# Get all the config environment variables
if [ -e /configuration/uploader.env ]; then
    source /configuration/uploader.env
fi

if [ "x${SCAN_TARGETS_PATH}" == "x" ]; then
    SCAN_TARGETS="/etc/openvas/scan-example.json"
else
    SCAN_TARGETS="${SCAN_TARGETS_PATH}"
fi
/usr/local/bin/setup-scan-targets.py ${SCAN_TARGETS}
sleep 2
sync; sync; sync

# Upload scan target/task definitions
/usr/local/bin/create-omp-scan-tasks.py -v -k simple
sleep 5; sync

# This script does everything else:
# - runs tasks one by one (in a random order)
# - generates and processes the report
# - uploads to S3
# All of the above happens one scanned subnet at a time, so we should be
# able to get results out earlier.
/usr/local/bin/run-omp-scan.py

# Once the scan has finished, wait for the specified time (default:
# about 3 hours) and exit.
# The container is shipped with restart-policy=always so this will
# eventually launch a new scan without human intervention.
sleep ${SLEEP_SECONDS_AFTER_FINISH:-11200}
