_author_ = 'thinksabin'

import argparse
import requests
import json
import os
import polling
from base64 import b64encode


DTRACK_SERVER = os.environ.get('DTRACK_SERVER')
DTRACK_API_KEY = os.environ.get('DTRACK_API_KEY')

API_PROJECT = '/api/v1/project'
API_PROJECT_LOOKUP = '/api/v1/project/lookup'
API_BOM_UPLOAD = '/api/v1/bom'
API_PROJECT_FINDING = '/api/v1/finding/project'
API_BOM_TOKEN = '/api/v1/bom/token'

DEFAULT_RISK = 'critical'
DEFAULT_SCORE = 3
DEFAULT_VERSION = '1.0.0'
DEFAULT_FILENAME = '../bom.xml'

DEFAULT_TRIGGER = 1


def get_project_without_version_id(host, key, project_name, version):
    url = host + API_PROJECT
    headers = {"content-type": "application/json", "X-API-Key": key}
    r = requests.get(url, headers=headers)
    response_dict = json.loads(r.text)

    for project in response_dict:

        if project_name == project.get('name') and project.get('version') == version:
            _project_id = project.get('uuid')
            return _project_id

def get_project_with_version_id(host, key, project_name, version):
    project_name = project_name
    version = version
    url = host + API_PROJECT_LOOKUP + '?name={}&version={}'.format(project_name, version)
    headers = {"content-type": "application/json", "X-API-Key": key}
    res = requests.get(url, headers=headers)
    response_dict = json.loads(res.text)
    return response_dict.get('uuid')

# read Bom.xml file convert into base64 for upload
def read_upload_bom(host, key, project_name, version, filename):
    print(project_name, version)

    with open(filename) as bom_file:
        _xml_data =  bom_file.read()
    #print(_xml_data)
    data = bytes(_xml_data, encoding='utf-8')

    bom_base64value = b64encode(data)
    encodedStr = str(bom_base64value, "utf-8")
    #bom_base64value = b64encode(_xml_data)
    _project_id = get_project_without_version_id(host, key, project_name, version)

    payload = {
        "project": _project_id,
        "bom": encodedStr
    }

    url = host + API_BOM_UPLOAD
    headers = {"content-type": "application/json", "X-API-Key": key}
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    response_dict = json.loads(r.text)
    print(response_dict)
    return response_dict.get('token')


def create_project(host, key, project_name, version):

    payload = {
                "name": project_name,
                "version": version
                }

    url = host + API_PROJECT
    headers = {"content-type": "application/json", "X-API-Key": key}
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    return r.status_code

def project_lookup_create(host, key, project_name, version):

    project_id = get_project_without_version_id(host, key, project_name, version)

    if project_id == None:
        status = create_project(host, key, project_name, version)
        if status == 201:
            uuid = get_project_without_version_id(host, key, project_name, version)
            #print(uuid)
            return uuid
    elif project_id != None:
        print(' Existing project/ version found: {} {} '.format(project_name, version))
        #print(project_id)
        return project_id


def get_project_finding_severity(host, key , project_id):

    critical_count = 0
    high_count = 0
    medium_count = 0
    unassigned_count = 0
    low_count  =0

    url = host + API_PROJECT_FINDING + '/{}'.format(project_id)
    headers = {"content-type": "application/json", "X-API-Key": key}
    r = requests.get(url, headers=headers)
    response_dict = json.loads(r.text)

    for component in response_dict:

        if component.get('vulnerability').get('severity') == 'CRITICAL':
            critical_count +=1
        if component.get('vulnerability').get('severity') == 'HIGH':
            high_count +=1
        if component.get('vulnerability').get('severity') == 'MEDIUM':
            medium_count +=1
        if component.get('vulnerability').get('severity') == 'LOW':
            low_count +=1
        if component.get('vulnerability').get('severity') == 'UNASSIGNED':
            unassigned_count +=1


    severity_count = {'CRITICAL': critical_count,
                      'HIGH': high_count,
                      'MEDIUM': medium_count,
                      'LOW': low_count,
                      'UNASSIGNED': unassigned_count
                      }
    print(severity_count)
    return severity_count


def get_bom_analysis_status(host, key, bom_token):

    url = host + API_BOM_TOKEN + '/{}'.format(bom_token)
    headers = {"content-type": "application/json", "X-API-Key": key}
    r = requests.get(url, headers=headers)
    response_dict = json.loads(r.text)
    return response_dict

def poll_response(response):
    status = json.loads(response.text).get('processing')
    return status == False

def poll_bom_token_being_processed(host, key, bom_token):
    url = host + API_BOM_TOKEN+'/{}'.format(bom_token)
    headers = {"content-type": "application/json", "X-API-Key": key}
    result = polling.poll(lambda: requests.get(url, headers=headers),
                          step=5,
                          poll_forever=True,
                          check_success=poll_response)
    return json.loads(result.text).get('processing')

def auto_project_create_upload_bom(host, key, project_name, version, risk, count, trigger, filename):

    print('Auto mode ON')

    project_uuid = project_lookup_create(host, key, project_name, version)
    bom_token = read_upload_bom(host, key, project_name, version, filename)
    poll_bom_token_being_processed(host, key, bom_token)
    severity_scores = get_project_finding_severity(host, key, project_uuid)

    if severity_scores.get(risk) >= int(count) and trigger == 1:
        print('Build failed to critical counts: {} >= {}'.format(risk, str(count)))
        exit(1)
    else:
        print('build successful', severity_scores.get(risk))
        exit(0)

def parse_cmd_args():
    parser = argparse.ArgumentParser(description='dtrack script for manual or in CI use',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', type=str,
                        help=' * url of dependencytrack host. eg. http://dtrack.abc.local:8080. OR set env $DTRACK_SERVER')
    parser.add_argument('-k', '--apikey', type=str,
                        help=' * api key of dependencytrack host. eg. adfadfe343g. OR set env $DTRACK_API_KEY')
    parser.add_argument('-p', '--project', type=str,
                        help=' * project name to be used in dependencytrack.eg: mywebapp. *')
    parser.add_argument('-v', '--version', type=str,
                        help=' * version of project in dependencytrack. eg. 1.0.0. *')
    parser.add_argument('-f', '--filename', type=str,
                        help='file path of sbom. eg. target/bom.xml, mybom.xml')
    parser.add_argument('-r', '--returncode', type=int,
                        help=' value 0 or 1 for Pass/ Fail. Use in Auto mode when job doesnt have to be '
                             'failed when number of issues detected more than count')
    parser.add_argument('-s', '--severity', type=str,
                        help='risk types to check. Use with Auto mode. eg: critical, high, medium, low, unassigned.'
                             'Default is critical')
    parser.add_argument('-c', '--count', type=str,
                        help='count of issue to set. Use with Auto mode. Fails the job of count of issue detected are higher or equal to count value. Default 3.')
    parser.add_argument('-a', '--auto', action="store_true",
                        help='auto creates project with version if not found in the dtrack server.'
                             ' sync and fail the job if any mentioned issues are found to be higher than default or set'
                             'count value.')
    args = parser.parse_args()

    if args.url is None:
        if DTRACK_SERVER != None:
            args.url = DTRACK_SERVER
        else:
            print('dtrack server required. set env $DTRACK_SERVER or use --url')
            exit(1)

    if args.apikey is None:
        if DTRACK_API_KEY != None:
            args.apikey = DTRACK_API_KEY
        else:
            print('api key required. set env $DTRACK_API_KEY or use --apikey')
            exit(1)

    if args.severity is None:
        args.severity = DEFAULT_RISK
    if args.returncode is None:
        args.returncode = DEFAULT_TRIGGER
    if args.count is None:
        args.count = DEFAULT_SCORE
    if args.version is None:
        args.version = DEFAULT_VERSION
    if args.filename is None:
        args.filename = DEFAULT_FILENAME

    return args

def main():

    args = parse_cmd_args()
    severity = args.severity.strip().upper()
    count = args.count
    returncode = args.returncode
    dt_server = args.url.strip()
    dt_api_key = args.apikey.strip()
    filename = args.filename.strip()

    if args.project and args.version:
        project_name = args.project.strip()
        version = args.version.strip()

        if args.auto:
            auto_project_create_upload_bom(dt_server, dt_api_key, project_name, version, severity, count, returncode, filename)
        else:
            project_uuid = project_lookup_create(dt_server, dt_api_key, project_name, version)
            bom_token = read_upload_bom(dt_server, dt_api_key, project_name, version, filename)
            print(project_uuid)
    else:
        print('Project Name and Version are required. Check help --help.')
        exit(1)


if __name__ == '__main__':
   main()


