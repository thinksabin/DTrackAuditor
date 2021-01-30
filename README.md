# DTrackAuditor

DTrackAuditor is the python script to facilitate usage of [DependencyTrack](https://dependencytrack.org/) in the CI, optionally failing the build based on different parameters.

### Features  

1. Auto mode for project creation given project name and version. Creates new project with version if already not found.
2. Auto mode useful for CI pipeline.
3. Optional filename path. Default is bom.xml
4. Filter based on severity type (critical, high, medium, low, unassigned) and numbers, e.g.: if number of critical is higher or equal to 10.
5. Check policy violations and fail if any found.
6. Return 0 or 1 exit status for Auto mode.

### Usage

#### Basic Usage

```
python3 dtrackauditor.py \
    -u 'http://mydtrack.local:8080' \
    -k 'mydtrackapikey' \
    -p myweb -v 1.0.0 \
    -f myweb/target/bom.xml \
    -a
```

If environment variable for `DTRACK_SERVER` and `DTRACK_API_KEY` are present then the usage can be direct.

```
python3 dtrackauditor.py  -p myweb -v 1.0.0 -a
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
