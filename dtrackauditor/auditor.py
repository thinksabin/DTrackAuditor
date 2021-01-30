import os
import sys
import json
import base64
import polling
import requests

PROXY_PATH = '/api'
API_PROJECT = PROXY_PATH + '/api/v1/project'
API_PROJECT_LOOKUP = PROXY_PATH + '/api/v1/project/lookup'
API_PROJECT_FINDING = PROXY_PATH + '/api/v1/finding/project'
API_BOM_UPLOAD = PROXY_PATH + '/api/v1/bom'
API_BOM_TOKEN = PROXY_PATH + '/api/v1/bom/token'
API_POLICY_VIOLATIONS = PROXY_PATH + '/api/v1/violation/project/%s'

class Auditor:

    @staticmethod
    def poll_response(response):
        status = json.loads(response.text).get('processing')
        return status == False

    @staticmethod
    def poll_bom_token_being_processed(host, key, bom_token):
        url = host + API_BOM_TOKEN+'/{}'.format(bom_token)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        result = polling.poll(
            lambda: requests.get(url, headers=headers),
            step=5,
            poll_forever=True,
            check_success=Auditor.poll_response
        )
        return json.loads(result.text).get('processing')

    @staticmethod
    def get_issue_details(component):
        return {
            'cveid': component.get('vulnerability').get('vulnId'),
            'purl': component.get('component').get('purl'),
            'severity_level': component.get('vulnerability').get('severity')
        }

    @staticmethod
    def get_project_policy_violations(host, key, project_id):
        url = host + API_POLICY_VIOLATIONS % project_id
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers)
        return json.loads(r.text)

    @staticmethod
    def check_vulnerabilities(host, key, project_uuid, rules, show_details):
        project_findings = Auditor.get_project_findings(host, key, project_uuid)
        severity_scores = Auditor.get_project_finding_severity(project_findings)
        print(severity_scores)

        vuln_details = list(map(lambda f: Auditor.get_issue_details(f), project_findings))

        if show_details == 'TRUE' or show_details == 'ALL':
            for items in vuln_details:
                print(items)

        for rule in rules:
            severity, count, fail = rule.split(':')
            fail = True
            if fail == 'false':
                fail = False
            s_issue_count = severity_scores.get(severity.upper())
            if s_issue_count is None:
                continue
            if s_issue_count >= int(count):
                print("Threshold for %s severity issues exceeded.")
                if fail is True:
                    sys.exit(1)

        print('Vulnerability audit resulted in no violations.')

    @staticmethod
    def check_policy_violations(host, key, project_uuid):
        policy_violations = Auditor.get_project_policy_violations(host, key, project_uuid)
        if not isinstance(policy_violations, list):
            print("Invalid response when fetching policy violations.")
            sys.exit(1)
        if len(policy_violations) == 0:
            print("No policy violations found.")
            return
        print("%d policy violations found:" % len(policy_violations))
        for violation in policy_violations:
            print("\t[%s] %s: %s" %  ( 
                violation.get('type'),
                violation.get('component'),
                violation.get('text')
            ) )
        sys.exit(1)

    @staticmethod
    def auto_project_create_upload_bom(host, key, project_name, version, rules, filename, show_details):
        print('Auto mode ON')
        print('Provide project name and version: ', project_name, version)
        project_uuid = Auditor.project_lookup_create(host, key, project_name, version)
        bom_token = Auditor.read_upload_bom(host, key, project_name, version, filename)
        Auditor.poll_bom_token_being_processed(host, key, bom_token)

        Auditor.check_policy_violations(host, key, project_uuid)
        Auditor.check_vulnerabilities(host, key, project_uuid, rules, show_details)

        sys.exit(0)

    @staticmethod
    def get_project_finding_severity(project_findings):
        severity_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'UNASSIGNED': 0
        }
        for component in project_findings:
            severity = component.get('vulnerability').get('severity') 
            severity_count[severity] += 1
        return severity_count

    @staticmethod
    def project_lookup_create(host, key, project_name, version):
        project_id = Auditor.get_project_without_version_id(host, key, project_name, version)
        if project_id is not None:
            print(' Existing project/ version found: {} {} '.format(project_name, version))
            return project_id
        status = Auditor.create_project(host, key, project_name, version)
        if status == 201:
            uuid = Auditor.get_project_without_version_id(host, key, project_name, version)
            return uuid

    @staticmethod
    def get_project_findings(host, key , project_id):
        url = host + API_PROJECT_FINDING + '/{}'.format(project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers)
        response_dict = json.loads(r.text)
        return response_dict

    @staticmethod
    def get_project_without_version_id(host, key, project_name, version):
        url = host + API_PROJECT
        headers = {
            "content-type": "application/json", 
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers)
        response_dict = json.loads(r.text)
        for project in response_dict:
            if project_name == project.get('name') and project.get('version') == version:
                _project_id = project.get('uuid')
                return _project_id

    @staticmethod
    def get_project_with_version_id(host, key, project_name, version):
        project_name = project_name
        version = version
        url = host + API_PROJECT_LOOKUP + '?name={}&version={}'.format(project_name, version)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        res = requests.get(url, headers=headers)
        response_dict = json.loads(res.text)
        return response_dict.get('uuid')

    @staticmethod
    def create_project(host, key, project_name, version):
        payload = {
            "name": project_name,
            "version": version
        }
        url = host + API_PROJECT
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.put(url, data=json.dumps(payload), headers=headers)
        return r.status_code

    @staticmethod
    def read_upload_bom(host, key, project_name, version, filename):
        _xml_data = None
        with open(os.path.join(os.path.dirname(__file__),filename)) as bom_file:
            _xml_data =  bom_file.read()
        data = bytes(_xml_data, encoding='utf-8')
        payload = {
            "project": Auditor.get_project_without_version_id(host, key, project_name, version),
            "bom": str(base64.b64encode(data), "utf-8")
        }
        headers = {
            "content-type": "application/json", 
            "X-API-Key": key
        }
        r = requests.put(host + API_BOM_UPLOAD, data=json.dumps(payload), headers=headers)
        response_dict = json.loads(r.text)
        return response_dict.get('token')
