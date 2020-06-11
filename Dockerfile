FROM kalilinux/kali-rolling:latest

# We do NOT delete apt state files between runs. Only packages.
# See below for more detailed reasoning.
# hadolint ignore=DL3005,DL3009
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget curl rsync \
    bzip2 nmap pnscan x42-plugins ike-scan \
    openvas-scanner openvas-manager \
    openvas-manager-common openvas-cli \
    && apt-get clean

# Pull in NVT scanning plugins
RUN /usr/sbin/greenbone-nvt-sync

### NOTE: We split the package installation into two steps and
### bypass the usual best practice. The reason is that installing
### the OpenVAS dependencies is a *lot* of work. As is the NVT database
### fetch.
###
### As long as the base image hasn't changed, any change in the packages
### listed below will trigger only a partial rebuild.

# hadolint ignore=DL3005
RUN apt-get update && \
    apt-get install -y \
    python3 awscli python3-boto3 && \
    rm -rf /var/lib/apt/lists/* && apt-get clean

COPY files/sbin/* /usr/local/sbin/
COPY files/bin/* /usr/local/bin/

# This overrides the default openv* daemon configs.
COPY files/conf/* /etc/openvas/

# Override builtin scan plugin values
COPY files/plugin_overrides/* /var/lib/openvas/plugins/

# The real scan targets are in configuration repo. This is for fallback
# and to provide a functional example inside an unconfigured container.
COPY files/scan*.json /etc/openvas/

CMD ["/usr/local/sbin/run-openvas.sh"]
