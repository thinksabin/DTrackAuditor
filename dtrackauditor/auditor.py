import sys
import json
import base64
import polling
import requests
from pathlib import Path

API_PROJECT = '/api/v1/project'
API_PROJECT_LOOKUP = '/api/v1/project/lookup'
API_PROJECT_FINDING = '/api/v1/finding/project'
API_BOM_UPLOAD = '/api/v1/bom'
API_BOM_TOKEN = '/api/v1/bom/token'
API_POLICY_VIOLATIONS = '/api/v1/violation/project/%s'
API_VERSION = '/api/version'

class AuditorException(Exception):
    """ Dependency-Track Auditor did not pass a test or had other run-time errors """

    INSTANT_EXIT = True
    """ Instead of raising an exception that may be caught by code,
    print the message and exit (legacy behavior for the CLI tool) """

    def __init__(self, message = "Dependency-Track Auditor did not pass a test"):
        if AuditorException.INSTANT_EXIT:
            print(message)
            sys.exit(1)

        self.message = message
        super().__init__(self.message)

class Auditor:
    @staticmethod
    def poll_response(response):
        status = json.loads(response.text).get('processing')
        return status == False

    @staticmethod
    def poll_bom_token_being_processed(host, key, bom_token, verify=True):
        print("Waiting for bom to be processed on dt server ...")
        print(f"Processing token uuid is {bom_token}")
        url = host + API_BOM_TOKEN+'/{}'.format(bom_token)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        result = polling.poll(
            lambda: requests.get(url, headers=headers, verify=verify),
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
    def get_project_policy_violations(host, key, project_id, verify=True):
        url = host + API_POLICY_VIOLATIONS % project_id
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            print(f"Cannot get policy violations: {r.status_code} {r.reason}")
            return {}
        return json.loads(r.text)

    @staticmethod
    def check_vulnerabilities(host, key, project_uuid, rules, show_details, verify=True):
        project_findings = Auditor.get_project_findings(host, key, project_uuid, verify=verify)
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
                message = "Threshold for %s severity issues exceeded." % severity.upper()
                if fail is True:
                    raise AuditorException(message)
                print(message)

        print('Vulnerability audit resulted in no violations.')

    @staticmethod
    def check_policy_violations(host, key, project_uuid, verify=True):
        policy_violations = Auditor.get_project_policy_violations(host, key, project_uuid, verify=verify)
        if not isinstance(policy_violations, list):
            raise AuditorException("Invalid response when fetching policy violations.")
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
        # TODO: A special Exception class with an actual copy of policy_violations[]
        raise AuditorException("%d policy violations found:" % len(policy_violations))

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
    def get_project_findings(host, key, project_id, verify=True):
        url = host + API_PROJECT_FINDING + '/{}'.format(project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            print(f"Cannot get project findings: {r.status_code} {r.reason}")
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_project_without_version_id(host, key, project_name, version, verify=True):
        url = host + API_PROJECT
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            print("Cannot get project without version id: {r.status_code} {r.reason}")
            return None
        response_dict = json.loads(r.text)
        for project in response_dict:
            if project_name == project.get('name') and project.get('version') == version:
                _project_id = project.get('uuid')
                return _project_id

    @staticmethod
    def get_project_with_version_id(host, key, project_name, version, verify=True):
        project_name = project_name
        version = version
        url = host + API_PROJECT_LOOKUP + '?name={}&version={}'.format(project_name, version)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        res = requests.get(url, headers=headers, verify=verify)
        if res.status_code != 200:
            print(f"Cannot get project id: {res.status_code} {res.reason}")
            return ""
        response_dict = json.loads(res.text)
        return response_dict.get('uuid')

    @staticmethod
    def read_bom_file(filename):
        """ Read original XML or JSON Bom file and re-encode it to DT server's liking. """
        print(f"Reading {filename} ...")
        filenameChecked = filename if Path(filename).exists() else str(Path(__file__).parent / filename)
        if filenameChecked != filename:
            print(f"Actually, found it as {filenameChecked} ...")

        if not Path(filenameChecked).exists():
            raise AuditorException(f"{filenameChecked} not found !")

        with open(filenameChecked, "r", encoding="utf-8-sig") as bom_file:
            # Reencode merged BOM file
            # Some tools like 'cyclonedx-cli' generates a file encoded as 'UTF-8 with BOM' (utf-8-sig)
            # which is not supported by dependency track, so we need to convert it as 'UTF-8'.
            _orig_data = bom_file.read().encode("utf-8")
            # # Encode BOM file into base64 then upload to Dependency Track
            data = base64.b64encode(_orig_data).decode("utf-8")
            # _orig_data = bom_file.read()
            # # # Encode BOM file into base64 then upload to Dependency Track
            # data = _orig_data
            #print(data)

            return data

        #return None

    @staticmethod
    def read_upload_bom(host, key, project_name, version, filename, auto_create, project_uuid=None, wait=False, verify=True):
        data = Auditor.read_bom_file(filename)

        print(f"Uploading {filename} ...")
        payload = {
            "bom": data
        }

        if project_uuid is not None:
            payload["project"] = project_uuid
            if auto_create is None:
                payload["autoCreate"] = False

        if auto_create is not None:
            payload["autoCreate"] = auto_create

        if project_name is not None:
            payload["projectName"] = project_name

        if version is not None:
            payload["projectVersion"] = version

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.put(host + API_BOM_UPLOAD, data=json.dumps(payload), headers=headers, verify=verify)
        if r.status_code != 200:
            raise AuditorException(f"Cannot upload {filename}: {r.status_code} {r.reason}")

        bom_token = json.loads(r.text).get('token')
        if bom_token and wait:
            Auditor.poll_bom_token_being_processed(host, key, bom_token)

    @staticmethod
    def get_dependencytrack_version(host, key, verify=True):
        print("getting version of OWASP DependencyTrack")
        print(host, key)
        url = host + API_VERSION
        headers = {
            "content-type": "application/json",
            "X-API-Key": key.strip()
        }
        print(url)
        res = requests.get(url, headers=headers, verify=verify)
        if res.status_code != 200:
            print(f"Cannot connect to the server {res.status_code} {res.reason}")
            return ""
        response_dict = json.loads(res.text)
        print(response_dict)
        return response_dict
