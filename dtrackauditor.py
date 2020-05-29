_author_ = 'thinksabin'

import argparse
import base64
import requests
import json
import os
import polling


DTRACK_SERVER = os.environ.get('DTRACK_SERVER')
DTRACK_API_KEY = os.environ.get('DTRACK_API_KEY')

API_PROJECT = '/api/v1/project'
API_PROJECT_LOOKUP = '/api/v1/project/lookup'
API_BOM_UPLOAD = '/api/v1/bom'
API_PROJECT_FINDING = '/api/v1/finding/project'
API_BOM_TOKEN = '/api/v1/bom/token'

DEFAULT_RISK = 'Critical'
DEFAULT_SCORE = 3
DEFAULT_VERSION = '1.0.0'
DEFAULT_FILENAME = 'bom.xml'

default_trigger = 1


def get_project_without_version_id(project_name, version=None):

    url = dt_server + API_PROJECT
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    r = requests.get(url, headers=headers)
    response_dict = json.loads(r.text)

    for project in response_dict:

        if project_name == project.get('name') and project.get('version') == version:
            _project_id = project.get('uuid')
            return _project_id

def get_project_with_version_id(project_name=None, version=DEFAULT_VERSION):
    project_name = project_name
    version = version
    url = dt_server + API_PROJECT_LOOKUP + '?name={}&version={}'.format(project_name, version)
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    res = requests.get(url, headers=headers)
    response_dict = json.loads(res.text)
    return response_dict.get('uuid')

# read Bom.xml file convert into base64 for upload
def read_upload_bom(project_name=None, version=None, filename=DEFAULT_FILENAME):

    with open(filename) as bom_file:
        _xml_data =  bom_file.read()
    file_base64value = base64.b64encode(_xml_data)

    _project_id = get_project_without_version_id(project_name, version)

    payload = {
        "project": _project_id,
        "bom": file_base64value
    }

    url = dt_server + API_BOM_UPLOAD
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    response_dict = json.loads(r.text)

    return response_dict.get('token')


def create_project(project_name, version):

    payload = {
                "name": project_name,
                "version": version
                }

    url = dt_server + API_PROJECT
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    r = requests.put(url, data=json.dumps(payload), headers=headers)
    return r.status_code

def project_lookup_create(project_name, version):

    project_id = get_project_without_version_id(project_name, version)

    if project_id == None:
        status = create_project(project_name, version)
        if status == 201:
            uuid = get_project_without_version_id(project_name, version)
            #print(uuid)
            return uuid
    elif project_id != None:
        print(' Existing project/ version found: {} {} '.format(project_name, version))
        #print(project_id)
        return project_id


def get_project_finding_severity(project_id):

    critical_count = 0
    high_count = 0
    medium_count = 0
    unassigned_count = 0
    low_count  =0

    url = dt_server + API_PROJECT_FINDING + '/{}'.format(project_id)
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
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


    severity_count = {'Critical': critical_count,
                      'High': high_count,
                      'Medium': medium_count,
                      'Low': low_count,
                      'Unassigned': unassigned_count
                      }
    print(severity_count)
    return severity_count


def get_bom_analysis_status(bom_token):

    url = dt_server + API_BOM_TOKEN + '/{}'.format(bom_token)
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    r = requests.get(url, headers=headers)
    response_dict = json.loads(r.text)

def poll_response(response):
    status = json.loads(response.text).get('processing')
    return status == False

def poll_bom_token_being_processed(bom_token):
    url = dt_server + API_BOM_TOKEN+'/{}'.format(bom_token)
    headers = {"content-type": "application/json", "X-API-Key": dt_api_key}
    result = polling.poll(lambda: requests.get(url, headers=headers),
                          step=5,
                          poll_forever=True,
                          check_success=poll_response)
    return json.loads(result.text).get('processing')

def auto_project_create_upload_bom(project_name, version=DEFAULT_VERSION, risk=DEFAULT_RISK, count=DEFAULT_SCORE):
    print('Auto mode ON')
    print('{} {} {} {} {}') .format(project_name, version, risk, count, default_trigger)

    project_uuid = project_lookup_create(project_name, version)
    bom_token = read_upload_bom(project_name, version)
    poll_bom_token_being_processed(bom_token)
    severity_scores = get_project_finding_severity(project_uuid)

    if severity_scores.get(risk) >= int(count) and default_trigger == int(1):
        print('build failed to critical counts')
        exit(1)
    else:
        print('build successful')
        exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='dtrack script for manual or in CI use',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-u', '--url', type=str, nargs='+',
                        help='url of dependencytrack host. eg. dtrack.abc.local:8080')
    parser.add_argument('-k', '--apikey', type=str, nargs='+',
                        help='api key of dependencytrack host. eg. dtrack.abc.local:8080')
    parser.add_argument('-p', '--project', type=str,nargs='+',
                        help='project name to be used in dependencytrack.eg: mywebapp')
    parser.add_argument('-v', '--version', type=str, nargs='+',
                        help='version of project in dependencytrack. eg. 1.0.0')
    parser.add_argument('-t', '--trigger', type=int, nargs='+',
                        help=' value 0 or 1 for Pass/ Fail. Use in Auto mode when job doesnt have to be '
                             'failed when number of issue are detected eg.')
    parser.add_argument('-r', '--risk', type=str, nargs='+',
                        help='risk to check in the version of project in dependencytrack. Use with Auto mode. eg. Critical, High, Medium, Low, Unassigned')
    parser.add_argument('-c', '--count', type=str, nargs='+',
                        help='count of issue to check. eg. 1.0.0')
    parser.add_argument('-a', '--auto', action="store_true",
                        help='auto creates project with version if not found in the dtrack server.'
                             ' sync and fail the job if any critical issue is found.')
    args = parser.parse_args()

    if args.url:
        print('over-riding env $DTRACK_SERVER with input')
        dt_server = args.url[0].strip()

    elif not args.url:
        if DTRACK_SERVER != None:
            dt_server = DTRACK_SERVER
        else:
            print('dtrack server required. set env $DTRACK_API_KEY or use --apikey')
            exit(1)
    else:
        print('Setting issue')


    if args.apikey:
        print('over-riding env $DTRACK_API_KEY with input')
        dt_api_key = args.apikey[0].strip()
    elif not args.apikey:
        if DTRACK_API_KEY != None:
            dt_api_key = DTRACK_API_KEY
        else:
            print('api key required. set env $DTRACK_API_KEY or use --apikey')
            exit(1)
    else:
        print('Setting issue')


    if args.project and args.version:
        project_name = args.project[0].strip()
        version = args.version[0].strip()

        if args.auto and not args.risk and not args.count and not args.trigger:
            auto_project_create_upload_bom(project_name, version)

        elif args.auto and args.risk and not args.count and not args.trigger:
            risk = args.risk[0]
            auto_project_create_upload_bom(project_name, version, risk)

        elif args.auto and args.risk and args.count and not args.trigger:
            risk = args.risk[0].strip()
            count = args.count[0].strip()
            auto_project_create_upload_bom(project_name, version, risk, count)

        elif args.auto and args.risk and args.count and args.trigger:
            risk = args.risk[0].strip()
            count = args.count[0].strip()
            default_trigger = args.trigger[0].strip()
            auto_project_create_upload_bom(project_name, version, risk, count)

        elif args.auto and args.risk and not args.count and args.trigger:
            risk = args.risk[0].strip()
            default_trigger = args.trigger[0]
            auto_project_create_upload_bom(project_name, version, risk)

        elif args.auto and args.trigger and not args.risk and not args.count:
            default_trigger = args.trigger[0]
            auto_project_create_upload_bom(project_name, version)

        else:
            project_uuid = project_lookup_create(project_name, version)
            bom_token = read_upload_bom(project_name, version)
            print(project_uuid)
    else:
        print('project name and version are required. Check help.')
        exit(1)