[![Scorecard supply-chain security](https://github.com/thinksabin/DTrackAuditor/actions/workflows/scorecard.yml/badge.svg)](https://github.com/thinksabin/DTrackAuditor/actions/workflows/scorecard.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/thinksabin/DTrackAuditor/badge)](https://securityscorecards.dev/viewer/?uri=github.com/thinksabin/DTrackAuditor/)
# DTrackAuditor

DTrackAuditor is the python script to ease usage of [DependencyTrack](https://dependencytrack.org/) in the CI, optionally failing the build based on different parameters.

# Development and Tests

* python 3.11.8
* DependencyTrack 4.10

### Features  

1. Auto mode for project creation given project name and version. Creates new project with version if already not found.
2. Auto mode useful for CI pipeline.
3. Optional filename path. Default is bom.xml
4. Filter based on severity type (critical, high, medium, low, unassigned) and numbers, e.g.: if number of critical is higher or equal to 10.
5. Check policy violations and fail if any found.
6. Return 0 or 1 exit status for Auto mode.

### Recommended usage
* For the latest update use clone this repo and use it as your preference.

### Quick Install

* Pypi
```
thinksabin@DESKTOP:~$ pip install dtrack-auditor
thinksabin@DESKTOP:~$ dtrackauditor
```
    
* Docker image
```
docker pull thinksabin/dtrackauditor:latest
```

* Git
```
git clone https://github.com/thinksabin/DTrackAuditor.git
```

### Usage

#### Basic Usage

* As a script:
```
python3 dtrackauditor.py \
    -u 'http://mydtrack.local:8080' \
    -k 'mydtrackapikey' \
    -p myweb -v 1.0.0 \
    -f myweb/target/bom.xml \
    -a
```

```
(.venv) PS C:\Users\dells\OneDrive\Documents\GitHub\DTrackAuditor\dtrackauditor> ..\.venv\Scripts\python.exe .\dtrackauditor.py -a -u 'http://mydtrack.local:8080' -k 'mydtrackapikey' -p ddweb -v 1.0.0 -f .\test\bom.xml --wait
```
If environment variable for `DTRACK_SERVER` and `DTRACK_API_KEY` are present then the usage can be direct:

```
python3 dtrackauditor.py  -p myweb -v 1.0.0 -a
```

If your DependencyTrack server is exposed through an HTTPS listener (e.g.
using an nginx or apache web-server as a reverse proxy for the UI and API
servers), and if this setup uses self-signed certificates or those issued by
a private (corporate) Certificate Authority, you may benefit from passing
a path to PEM file with the trust chain using `DTRACK_SERVER_CERTCHAIN`
environment variable or the `-C`/`--certchain` command-line argument.
Such argument may also be `none` to trust any HTTPS server blindly.

* As a Docker container:
```
docker run --rm -v $PWD:/tmp \
    thinksabin/dtrackauditor -- \
    required parameters as examples
```

#### Vulnerability Rules

Auto mode for CI/CD with support for rules.

```
python3 dtrackauditor.py \
    -u http://mydtrack.local:8080 \
    -k mydtrackapikey \
    -p hello \
    -v 8.0.0 \
    -a \
    -r critical:1:true,high:2:true,medium:10:true,low:10:false
```

The rules are a list of:

```
<severity>:<count>:<action>
```

Where:

 * severity: Either `critical`, `high`, `medium`, `low`, or `unassigned`
 * count: If the count of the issues for the `severity` is greater or equal, trigger `action`
 * action: `true` to fail the test, `false` to just display a warning (default is `true`)

#### Policy Violations

DtrackAuditor return with code 1 (fails the test) in case any Policy Violations detected. This feature is not configurable and cannot be disabled using command line options.

# For enhancement
Please create issues for bug reports and suggestions. Thanks.
