# DTrackAuditor
DTrackAuditor is the python script to facilitate usage of [DependencyTrack](https://dependencytrack.org/) in the CI.

Specially made for the non Jenkins CI environment. DependencyTrack already has Jenkins plugin to be used https://plugins.jenkins.io/dependency-track/

This script helps to use DependencyTrack in the CI pipeline, failing the build based on different parameters.

The Golang based similar tool already exists here and is easy to use: https://github.com/ozonru/dtrack-audit


#### Setup
Install all the dependencies libraries required.  
Requirement = Python 3.8 or above  
Tested on Python 3.8 


#### Features  

1. Auto mode for project creation given project name and version. Creates new project with version if already not found.
2. Auto mode useful for CI pipeline.
3. Optional filename path. Default is bom.xml
4. Filter based on severity type (critical, high, medium, low, unassigned) and numbers. 
eg. if number of critical is higher or equal to 10. Default is critical with 3 counts
5. Return 0 or 1 exit status for Auto mode.


#### Usage

`python dtrackauditor.py -u 'http://mydtrack.local:8080' -k 'mydtrackapikey' -p myweb -v 1.0.0 -f myweb/target/bom.xml -a`

If environment variable for DTRACK_SERVER and DTRACK_API_KEY are present then the usage can be direct.


`python dtrackauditor.py  -p myweb -v 1.0.0 -a`

Auto mode for CI/ CD. Use risk, count and trigger flags to change defaults.
`python dtrackauditor.py -u http://mydtrack.local:8080 -k mydtrackapikey -p hello -v 8.0.0 -a -s critical -c 20 -r 0 -l true`


For more please use --help

`python dtrackauditor.py  --help`

---

#### Docker usage

docker run --rm  -v $PWD:/tmp thinksabin/dtrackauditor --url http://192.168.43.221:8081 --apikey XYQAQHW1kECL98LTaxUDjh -f /tmp/bom.xml -p myprojectname -v 2.0.0 -a

#### Pip usage
pip install dtrack-auditor

### Setup usage
Clone the repo from the master branch for the latest test code commits.
python3 setup.py