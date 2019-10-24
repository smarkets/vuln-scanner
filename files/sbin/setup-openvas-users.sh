#!/bin/bash

set -xeu

# We'll need "users" (like DB roles) for openvasmd to actually do
# anything.
pwd_out=$(/usr/sbin/openvasmd --create-user=scanner --role=Admin)
passwd_=$(echo ${pwd_out} | cut -d "'" -f 2)
echo ${passwd_} > /tmp/openvas-scanner-pass

# For ease of use, create ~/omp.config
cat >> ${HOME}/omp.config << __EOF
[Connection]
host=localhost
port=9390
username=scanner
password=${passwd_}
__EOF
