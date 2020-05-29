# DTrackAuditor
DTrackAuditor is the python script to facilitate usage of DependencyTrack in the CI.

Specially made for the non Jenkins CI environment. DependencyTrack already has Jenkins plugin to be used https://plugins.jenkins.io/dependency-track/

This script helps to use DependencyTrack in the CI pipeline, failing the build based on different parameters.


Setup
Install all the dependencies libraries required. Based on Python 3 and above. Developed upon Python 3.8


Usage
------

`python dtrackauditor.py -u 'http://mydtrack.local:8080' -k 'myapikey' -p myweb -v 1.0.0 -f myweb/target/bom.xml -a`

If environment variable for DTRACK_SERVER and DTRACK_API_KEY are present then the usage can be direct.


`python dtrackauditor.py  -p myweb -v 1.0.0 -a`

For more please use --help

`python dtrackauditor.py  --help`