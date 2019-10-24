# Automated vulnerability scanner

The vulnerability scanner automates the discovery and reporting of
*known and detected* vulnerabilities in your fleet. It is designed to
provide data to answer these two questions:

1. Do I know what is running in my fleet?
1. Do I know what vulnerabilities are present?

## Why did you build this?

Because modern distributed systems tend to run a lot of software, and
not all of it is easily accounted for. Knowing what components have been
implicitly brought in and exposed is simply not optional. And discovering
what known vulnerabilities those same components come with is absolutely
necessary.

What easier way would there be than to have someone scan your entire
network and report on the findings? One could commission a pentest,
but internal pentests remain point-in-time exercises and obviously can't
help with tracking the ongoing state. One would have to have an internal
pentester running their toolkits all the time. But that would get
boring for them, really fast.

Doing repetitive tasks is something computers are *really* good at.
Humans less so.

For avoidance of doubt: there are companies that specialise in providing
software and services for these purposes - the term used in marketing is
"asset tracking".

The scanner setup we built at Smarkets is designed to provide a
reasonable baseline. It does not attempt to be state-of-the-art, or
provide the most bells and whistles. It certainly doesn't try to look
shiny. Its sole purpose is to provide a functional, continuous software
asset and vulnerability tracking system, and to allow an organisation to
properly evaluate their needs.

Monitoring software and vulnerability lifecycle is a process that must
be seen as a long-term, ongoing activity. Acquiring a third-party tool,
and setting it up with an evaluation license imposes a fixed time limit
for discovering its usefulness and/or value. More likely than not, the
license expires before there is enough data to do a proper evaluation.

(Personal note: from the experience gained with the scanner running, it
takes anything from three to six months to reliably observe how things
change over time.)

# Technical details

The automated vulnerability scanner is built on OpenVAS, which in turn
is the scanning backend of Greenbone security suite. (Effectively: fork
of Nessus, after Tenable pulled the drawbridge.)

The scanner runs continously, and relies on the container having its
restart policy set to "always". After it has finished scanning of all the
configured subnets, it will sleep by default for ~3h and exit
gracefully. At this point the restart policy will launch it again, and a
new fleet sweep will begin.

Once the scan of a subnet is complete, the generated JSON report is
automatically uploaded to S3, in the bucket and prefix specified in
config (see values.yaml); the raw reports are huge XML documents, but we
won't be storing those if we can avoid it. Instead we parse them in the
container and produce more useful documents.

The scanner is built of a few components:

```
                             +----------+
                             |  SQLite  | <----+
                             +----------+      |
                                               |
+---------+                             +------------------------+
|  Redis  |         +-------------------|   OpenVASMD            |
+---------+         |                   |   (Management Daemon)  |
    ^               V                   +------------------------+
    |     +-------------------+             ^
    +-----| OpenVASSD         |             |
          | (Scanning Daemon) |             |
          +-------------------+             |
                                   +---------------------------+
                                   |  OMP command line client  |
                                   +---------------------------+
```

The management daemon maintains its state in the SQLite database. This
state is cleared, by removing the database files, at the start of each
scanning run. There are scan options to use already learned information
to process new scans quicker, but in practice trying to work with an
existing state only makes things more difficult.

The scanning daemon is the component responsible for running the actual
scans, controlled by the management daemon. Normally the communication
with management daemon happens via a GUI, but we are running the scans
completely headless.

There is no sane API to communicate with the management daemon. Instead
all commands are sent with the CLI client. The command reference can be
found here:
http://docs.greenbone.net/API/OMP/omp-7.0.html#command_create_target

Yes, all commands are XML documents. Before you read further, have an
aspirin.

## Scanner run logic

The container is completely stateless. Every run goes through the
following logical steps:

1. Redis is launched with OpenVAS specific config
1. OpenVASSD is started
1. OpenVASMD is started
1. The known vulnerabilites are imported, and the progress blocked until
   the import has completed (this is where daemons write to redis and
   sqlite)
1. A user "role" is created with a randomly generated password, and the
   access set up automatically for this container incarnation
1. Scan targets are set up
1. Scan tasks are created, to associate a "scan job" with each of the
   targets from the previous step
1. The scan is launched (that's a lot of steps to get this far, to be
   honest)
1. _we wait_
1. Once the scan has finished, the XML report is retrieved and
   transformed into a less unfriendly JSON document
1. Each JSON document is uploaded to the S3 bucket directory

You can further process the JSON reports with the included sample script:
`files/misc/vuln-reports.py`


## Target Syntax

Normally you don't need to know about the XML document syntax. However, if
you want to add new targets, some knowledge of the document format is
necessary.

In the most basic form a target document will look like this:

```
<create_target>
    <name>Human-readable scan name</name>
    <hosts>[a single CIDR network specification]</hosts>
</create_target>
```

There are two crucial things to remember:

1. a task can have ONLY ONE network block
1. a task name has to be unique

This is potentially very confusing, because most documentation found
online allows to set multiple target networks through GUIs. In reality,
the GUI hides the ugly truth - that for each network there will be a
separate task.

Although OpenVAS uses UUIDs internally for everything, the
human-readable names have to be unique. There is a configuration option
to generate suffixes on demand, but we don't use it. It's easier to have
scan names match exactly the name specified in config.

# Target configuration

The configuration for scanning is read from the path in environment
variable `SCAN_TARGETS_PATH`. This is a JSON file, with a
straightforward format:

```
{
    "safe_ports": "T:<port ranges>,U:<port ranges>",
    "full_ports": "T:<port ranges>,U:<port ranges>",
    "targets": [
        {
            "name": "Target subnet name",
            "cidr": "<CIDR netmask>",
            "port_list": "<name of port list specification key">,
        },
        {
            "name": "Target subnet name",
            "cidr": "<CIDR netmask>",
            "port_list": "<name of port list specification key">,
            "blacklist": <list of IP addresses, if any>,
        },
        [...]
    ]
}
```

The keys before the target list could be named anything, but using
`safe_ports` and `full_ports` makes for an easy, binary selection. If
you need different port combination for different networks, you can
specify any amount of them with arbitrary key names. These keys will be
referenced from the target specification.

The actual targets are dictionaries. The keys `name`, `cidr` and
`port_list` are mandatory. If you need to avoid hitting some hosts, use
the optional `blacklist` key. Here is an example of a network with two
blacklisted hosts:

```
{
    "name": "Public DMZ, Sao Paulo",
    "cidr": "10.40.250.0/24",
    "port_list": "full_ports",
    "blacklist": [ "10.40.250.2", "10.40.250.193" ]
}
```

**NOTE:** The target names MUST be unique, due to OpenVAS's internal
implementation.

# Building and running

Before you start, create a file called uploader.env with the following
content:

```
export AWS_ACCESS_KEY_ID=<uploader key id>
export AWS_SECRET_ACCESS_KEY=<uploader secret>
export AWS_DEFAULT_REGION=<as desired>
export SCAN_TARGETS_PATH="/configuration/your-scan-config.json"
export REPORT_UPLOAD_BUCKET=<s3 bucket you want to use>
export REPORT_NAME_PREFIX=<s3 path prefix you want for the reports>
```

This file will be read in during the scanner launch from the
configuration directory. Alternatively you can supply all the
environment variables via some other means, but unless you have access
to an orchestrator, the file is likely the most convenient way.

To build the image, simply run:

```
docker build . -t vuln-scanner
```

Running the container is a bit more involved:

```
docker run --tty \
    --name=vuln-scanner \
    -v /dev/shm:/var/lib/openvas/mgr \
    -v /path/to/configuration:/configuration \
    --network=host \
    --cap-add=NET_RAW --cap-add=NET_ADMIN \
    --restart \
    vuln-scanner
```

The options above probably require some context.

The scanner requires both `NET_RAW` and `NET_ADMIN` capabilities in
order to run the nmap scan correctly. If either one is missing, the nmap
run will never produce any results and host discovery will simply
come up empty.

The two volumes are somewhat trickier. Configuration volume from host is
an easy and common practice, but the use of `/dev/shm` from the host for
anything may look suspicious. This is to guarantee that the path resides
on a `tmpfs` volume, which is necessary for reliability.

The path `/var/lib/openvas/mgr` is where the scanner keeps its SQLite
data (and its state). The code exercises certain low-level SQLite APIs
and treats all I/O timeouts as failures.  When the database files are on
a `tmpfs` volume, the probability of such timeouts are notably smaller.
Failures without `tmpfs` would manifest usually within hours.

The same effect could be achieved with `--tmpfs=/var/lib/openvas/mgr`
but for debugging purposes it is easier if the path is visible from the
host side.


## Minor details

The generated raw reports are verbose XML. The processed JSON versions
are often less than 1/10th of the size.

The target setup code in `files/bin/setup-scan-targets.py` does manual
CIDR network expansion to work around a weird bug in how the support
library works. The library, libopenvas_base.so, is supposed to expand
CIDR networks into lists of individual IP addresses. However, that code
may not work reliably. We have seen it produce both empty and correct
results, with the same OpenVAS packages. So to be on the safe side, we
avoid calling it at all.
