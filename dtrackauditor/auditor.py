import os
import sys
import json
import time
import base64
import inspect
import polling
import requests
from pathlib import Path

API_PROJECT = '/api/v1/project'
API_PROJECT_CLONE = '/api/v1/project/clone'
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
            print("AuditorException.INSTANT_EXIT: " + message)
            sys.exit(1)

        self.message = message

        super().__init__(self.message)

class AuditorRESTAPIException(AuditorException):
    """ Dependency-Track Auditor had a run-time error specifically due to REST API unexpected situation """

    def __init__(self, message = "Dependency-Track Auditor had a REST API unexpected situation", result = None):
        if AuditorException.INSTANT_EXIT:
            print("AuditorRESTAPIException.INSTANT_EXIT: " + AuditorRESTAPIException.stringify(message, result))
            sys.exit(1)

        self.result = result
        """ Result of an HTTP query which caused the exception, if any """

        super().__init__(message)

    @staticmethod
    def stringify(message, result, showFullResultText = False):
        s = f"{message}"
        try:
            if result is not None:
                s += f": HTTP-{result.status_code} {result.reason}"
                if result.text is None or len(result.text) == 0:
                    s += " <empty response content>"
                elif len(result.text) < 128 or showFullResultText:
                    s += f" => {result.text}"
                else:
                    s += f" <response content length is {len(result.text)}>"
        except Exception as ignored:
            pass
        return s

    def __str__(self):
        return AuditorRESTAPIException.stringify(self.message, self.result)


class DTrackClient:
    """ Instance of Dependency-Track server client with pre-configured credentials, e.g.

    dtc = DTrackClient().initByEnvvars().sanityCheck()

    Relies on the Auditor class for actual logic. """

    def __init__(self, base_url: str|None = None, api_key: str|None = None, ssl_verify: str|bool|None = None):
        """ Initializer from basic string/bool/int values.
        See also initByEnvvars() for follow-up from environment variables (can keep "None" here then).
        """

        self.base_url: str|None = base_url
        """ Dependency-Track server base URL, e.g. http://dtrack.abc.local:8080

        Any trailing slash is stripped. """

        self.api_key: str|int|None = api_key
        """ Dependency-Track server API Key with permissions for needed manipulations. """

        self.ssl_verify: str|bool|None = ssl_verify
        """ SSL/TLS verification setting (False to trust anything, True to use system cert store,
        or a string path name to file with server+CA certs).

        Note again, that an *optional* TLS certificate chain (server, CA) can be provided here.
        """

        self.normalize()

    def isBaseUrlHTTPS(self):
        return str(self.base_url).lower().startswith('https://')

    def normalizeBaseUrl(self):
        if isinstance(self.base_url, str):
            #self.base_url = self.base_url.strip().rstrip('/')
            self.base_url = self.base_url.strip()
            while len(self.base_url) > 0 and self.base_url[-1] == '/':
                self.base_url = self.base_url[:-1]
        return self.base_url

    def normalizeApiKey(self):
        if isinstance(self.api_key, str):
            self.api_key = self.api_key.strip()
        return self.api_key

    @staticmethod
    def tryAsBool(
            val,
            meaningOfNone: bool|None = False,
            meaningOfEmptyString: bool|None = True
    ):
        """ Converts certain values of "val" (case-insensitive string or
        integer) into a bool. Special consideration for None and "None"
        (string), and for an empty string (after stripping whitespace).
        If there is no match, keeps and returns "val" as is.
        """
        if val is None:
            if meaningOfNone is not None:
                val = meaningOfNone
        else:
            if isinstance(val, str) or isinstance(val, int):
                tmp = str(val).strip().lower()
                if len(tmp) > 0:
                    if tmp in ['true', 'yes', 'on', '1']:
                        val = True
                    if tmp in ['false', 'no', 'off', '0']:
                        val = False
                    if meaningOfNone is not None and tmp == "none":
                        val = meaningOfNone
                else:
                    if meaningOfEmptyString is not None:
                        val = meaningOfEmptyString

        return val

    def normalizeSslVerify(self):
        if self.ssl_verify is None:
            if self.base_url is None:
                return None

            self.ssl_verify = self.isBaseUrlHTTPS()
            if Auditor.DEBUG_VERBOSITY > 0:
                # Note: This can get reported twice for a chain of events like
                #   dtc = DTrackClient().initByEnvvars().sanityCheck()
                # (once from init() defaults and once from a missing envvar value)
                print("Auditor.normalizeSslVerify(): defaulting ssl_verify=%s for base URL %s%s" % (
                    str(self.ssl_verify),
                    str(self.base_url),
                    " : DependencyTrack server is HTTPS but no path to file with cert chain was provided (may be required if not using a well-known CA)" if self.ssl_verify else ""
                ))

        if isinstance(self.ssl_verify, str):
            self.ssl_verify = self.ssl_verify.strip()

        self.ssl_verify = DTrackClient.tryAsBool(self.ssl_verify)

        if isinstance(self.ssl_verify, str) and len(self.ssl_verify) > 0:
            if os.path.exists(self.ssl_verify) and not os.path.isabs(self.ssl_verify):
                # Presumably a relative pathname was provided, and actually
                # one such exists compared to current working directory; so
                # be sure to use the intended file even if we chdir() later
                # in the consuming program:
                tmp = os.path.sep.join([os.getcwd(), self.ssl_verify])
                if os.path.exists(tmp):
                    if Auditor.DEBUG_VERBOSITY > 0:
                        print("Auditor.normalizeSslVerify(): remembering cert path relative to CWD: %s => %s" % (str(self.ssl_verify), tmp))
                    self.ssl_verify = tmp

            if not os.path.exists(self.ssl_verify) and not os.path.isabs(self.ssl_verify):
                # Is there some cert file distributed with the program
                # (so the specified non-absolute path is relative to *it*)?
                tmp = os.path.sep.join([
                    os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))),
                    self.ssl_verify
                ])
                if os.path.exists(tmp):
                    if Auditor.DEBUG_VERBOSITY > 0:
                        print("Auditor.normalizeSslVerify(): remembering cert path relative to program/module: %s => %s" % (str(self.ssl_verify), tmp))
                    self.ssl_verify = tmp

        return self.ssl_verify

    def normalize(self):
        self.normalizeBaseUrl()
        self.normalizeApiKey()
        self.normalizeSslVerify()
        return self

    def initByEnvvars(
            self,
            base_url_varname: str|None = 'DTRACK_SERVER',
            base_url_default: str|None = None,
            api_key_varname: str|None = 'DTRACK_API_KEY',
            api_key_default: str|None = None,
            ssl_verify_varname: str|None = 'DTRACK_SERVER_CERTCHAIN',
            ssl_verify_default: str|None = None
    ): # -> DTrackClient:
        """ (Re-)initialize settings from environment variables whose names
        are specified by arguments, with optional fallback default values.
        You can specify something_varname=None to avoid (re-)setting that value.
        """
        if base_url_varname is not None:
            self.base_url = os.environ.get(base_url_varname, base_url_default)
            if self.base_url is None or len(self.base_url) == 0:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print("Auditor.initByEnvvars(): WARNING: no URL found via envvar '%s'" % self.base_url)

        if api_key_varname is not None:
            self.api_key = os.environ.get(api_key_varname, api_key_default)
            if (self.api_key is None or len(self.api_key) == 0) and Auditor.DEBUG_VERBOSITY > 0:
                print("Auditor.initByEnvvars(): WARNING: no API Key found via envvar '%s'" % self.api_key)

        if ssl_verify_varname is not None:
            self.ssl_verify = os.environ.get(ssl_verify_varname, ssl_verify_default)
            if self.ssl_verify is None or len(self.ssl_verify) == 0:
                if Auditor.DEBUG_VERBOSITY > 0 and str(self.base_url).lower().startswith('https://'):
                    print("Auditor.initByEnvvars(): WARNING: no explicit verification toggle or cert chain found via envvar '%s'" % self.ssl_verify)

        self.normalize()

        # Allow chaining like:
        #   dtc = DTrackClient().initByEnvvars()
        return self

    def sanityCheck(self): # -> DTrackClient:
        """ Raise exceptions if required values are not present in this instance. """
        if self.base_url is None or not isinstance(self.base_url, str) or len(self.base_url) == 0:
            raise AuditorException('DependencyTrack server URL is required. Set Env $DTRACK_SERVER, e.g.: http://dtrack.my.local:8080')

        if self.api_key is None or not isinstance(self.api_key, str) or len(self.api_key) == 0:
            raise AuditorException('DependencyTrack API key is required. Set Env $DTRACK_API_KEY')

        if str(self.base_url).lower().startswith('https://'):
            if self.ssl_verify is None:
                raise AuditorException('DependencyTrack SSL verification is not set properly. Set Env $DTRACK_SERVER_CERTCHAIN to path name or boolean value')

            if isinstance(self.ssl_verify, str):
                if len(self.ssl_verify) == 0:
                    raise AuditorException('DependencyTrack SSL verification is not set properly: seems set but is empty. Set Env $DTRACK_SERVER_CERTCHAIN to path name or boolean value')
                if not Path(self.ssl_verify).exists():
                    raise AuditorException("DependencyTrack SSL verification is not set properly: seems set but specified path to file with cert chain '%s' does not exist. Set Env $DTRACK_SERVER_CERTCHAIN to path name or boolean value" % str(self.ssl_verify))
            else:
                if not isinstance(self.ssl_verify, bool):
                    raise AuditorException('DependencyTrack SSL verification is not set properly. Set Env $DTRACK_SERVER_CERTCHAIN to path name or boolean value')

        # Allow chaining like:
        #   dtc = DTrackClient().initByEnvvars().sanityCheck()
        return self

    def __str__(self):
        return "DTrackClient instance for '%s' identified by '%s'; SSL/TLS verification: %s" % (
            str(self.base_url), str(self.api_key), str(self.ssl_verify)
        )

    def poll_bom_token_being_processed(self, bom_token, wait=True):
        return Auditor.poll_bom_token_being_processed(
            host=self.base_url, key=self.api_key,
            bom_token=bom_token,
            wait=wait, verify=self.ssl_verify)

    def poll_project_uuid(self, project_id, wait=True):
        return Auditor.poll_project_uuid(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            wait=wait, verify=self.ssl_verify)

    def delete_project_uuid(self, project_id, wait=True):
        return Auditor.delete_project_uuid(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            wait=wait, verify=self.ssl_verify)

    def delete_project(self, project_name, wait=True):
        return Auditor.delete_project(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            wait=wait, verify=self.ssl_verify)

    def get_project_policy_violations(self, project_id):
        return Auditor.get_project_policy_violations(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)

    def check_vulnerabilities(self, project_id, rules, show_details):
        return Auditor.check_vulnerabilities(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            rules=rules,
            show_details=show_details,
            verify=self.ssl_verify)

    def check_policy_violations(self, project_id):
        return Auditor.check_policy_violations(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)

    def get_project_findings(self, project_id):
        return Auditor.get_project_findings(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)

    def get_project_list(
            self,
            project_name=None,
            exclude_inactive=False,
            exclude_children=False
    ):
        return Auditor.get_project_list(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            exclude_inactive=exclude_inactive,
            exclude_children=exclude_children,
            verify=self.ssl_verify)

    def get_project_without_version_id(self, project_name, version):
        return Auditor.get_project_without_version_id(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            version=version,
            verify=self.ssl_verify)

    def get_project_with_version_id(self, project_name, version):
        return Auditor.get_project_with_version_id(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            version=version,
            verify=self.ssl_verify)

    def read_upload_bom(
            self,
            project_name, version, filename, auto_create,
            project_id=None,
            parent_project=None, parent_version=None, parent_id=None,
            wait=False):
        return Auditor.read_upload_bom(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            version=version,
            filename=filename,
            auto_create=auto_create,
            project_uuid=project_id,
            parent_project=parent_project,
            parent_version=parent_version,
            parent_uuid=parent_id,
            wait=wait, verify=self.ssl_verify)

    def clone_project_by_uuid(
            self, old_project_version_id,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=False, safeSleep=3):
        return Auditor.clone_project_by_uuid(
            host=self.base_url, key=self.api_key,
            old_project_version_uuid=old_project_version_id,
            new_version=new_version,
            new_name=new_name,
            includeALL=includeALL,
            includeACL=includeACL,
            includeAuditHistory=includeAuditHistory,
            includeComponents=includeComponents,
            includeProperties=includeProperties,
            includeServices=includeServices,
            includeTags=includeTags,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)

    def clone_project_by_name_version(
            self, old_project_name, old_project_version,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=False, safeSleep=3):
        return Auditor.clone_project_by_name_version(
            host=self.base_url, key=self.api_key,
            old_project_name=old_project_name,
            old_project_version=old_project_version,
            new_version=new_version,
            new_name=new_name,
            includeALL=includeALL,
            includeACL=includeACL,
            includeAuditHistory=includeAuditHistory,
            includeComponents=includeComponents,
            includeProperties=includeProperties,
            includeServices=includeServices,
            includeTags=includeTags,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)

    def set_project_active(self, project_id, active=True, wait=False):
        return Auditor.set_project_active(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            active=active,
            wait=wait, verify=self.ssl_verify)

    def clone_update_project(
            self, filename, new_version,
            new_name=None,
            old_project_version_id=None,
            old_project_name=None, old_project_version=None,
            activate_old=None, activate_new=None,
            deleteExistingClone=False,
            parent_project=None, parent_version=None, parent_id=None,
            includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=True, safeSleep=3):
        return Auditor.clone_update_project(
            host=self.base_url, key=self.api_key,
            filename=filename,
            new_version=new_version,
            new_name=new_name,
            old_project_version_uuid=old_project_version_id,
            old_project_name=old_project_name,
            old_project_version=old_project_version,
            activate_old=activate_old,
            activate_new=activate_new,
            deleteExistingClone=deleteExistingClone,
            parent_project=parent_project,
            parent_version=parent_version,
            parent_uuid=parent_id,
            includeALL=includeALL,
            includeACL=includeACL,
            includeAuditHistory=includeAuditHistory,
            includeComponents=includeComponents,
            includeProperties=includeProperties,
            includeServices=includeServices,
            includeTags=includeTags,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)

    def get_dependencytrack_version(self):
        return Auditor.get_dependencytrack_version(
            host=self.base_url, key=self.api_key,
            verify=self.ssl_verify)


class Auditor:
    DEBUG_VERBOSITY = 3
    """ Library code is peppered with direct prints for the associated
    utility; some messages are only shown if Auditor.DEBUG_VERBOSITY
    is sufficiently high.

    For historic reasons (single-purpose client) this class is full of
    static methods, with OOP-style instances of a separate DTrackClient
    class added later to avoid the hassle of passing the same arguments
    around. It could not be squashed into the same class (at least not
    while using same method names). """

    @staticmethod
    def poll_response(response):
        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("poll_response()", response))
        if response.status_code != 200:
            return False
        status = json.loads(response.text).get('processing')
        return (status == False)

    @staticmethod
    def uuid_present(response):
        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("uuid_present()", response))
        if response.status_code != 200:
            return False
        uuid = json.loads(response.text).get('uuid')
        return (uuid is not None and len(uuid) > 0)

    @staticmethod
    def entity_absent(response):
        """ Returns a success if specifically the request returned HTTP-404 """
        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("entity_absent()", response))
        if response.status_code == 404:
            return True
        return False

    @staticmethod
    def poll_bom_token_being_processed(host, key, bom_token, wait=True, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (bom_token is not None and bom_token != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print("Waiting for bom to be processed on dt server ...")
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"Processing token uuid is {bom_token}")
        url = host + API_BOM_TOKEN+'/{}'.format(bom_token)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
            print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")
        # NOTE: poll_forever!=False, ever!
        if wait:
            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else None),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.poll_response
            )
        else:
            result = requests.get(url, headers=headers, verify=verify)
        return json.loads(result.text).get('processing')

    @staticmethod
    def poll_project_uuid(host, key, project_uuid, wait=True, verify=True):
        """ Polls server until 'project_uuid' info is received.
        Checks if that info's 'uuid' matches (fails an assert()
        otherwise) and returns the object decoded from JSON.
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_uuid is not None and project_uuid != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"Waiting for project uuid {project_uuid} to be reported by dt server ...")
        url = host + API_PROJECT + '/{}'.format(project_uuid)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
            print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")
        # NOTE: poll_forever!=False, ever!
        if wait:
            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else None),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.uuid_present
            )
        else:
            result = requests.get(url, headers=headers, verify=verify)
        resObj = json.loads(result.text)
        assert (resObj["uuid"] == project_uuid)
        return resObj

    @staticmethod
    def delete_project_uuid(host, key, project_uuid, wait=True, verify=True):
        """ Polls server until 'project_uuid' info is received.
        Checks if that info's 'uuid' matches (fails an assert()
        otherwise) and returns the object decoded from JSON.
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_uuid is not None and project_uuid != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"Deleting project uuid {project_uuid} (if present on dt server) ...")
        url = host + API_PROJECT + '/{}'.format(project_uuid)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        try:
            result = requests.delete(url, headers=headers, verify=verify)
        except Exception as ex:
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Deletion request for project uuid {project_uuid} failed: {ex}")
            pass

        if result is not None:
            if 200 <= result.status_code < 300:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Deletion request for project uuid {project_uuid} succeeded: {result.status_code} {result.reason} => {result.text}")
            elif result.status_code == 404:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Deletion request for project uuid {project_uuid} was gratuitous (no such object already): {result.status_code} {result.reason} => {result.text}")
                return
            else:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Deletion request for project uuid {project_uuid} failed: {result.status_code} {result.reason} => {result.text}")
                # TODO? raise AuditorRESTAPIException(f"Deletion request for project uuid {project_uuid} failed, r)

        if wait:
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Checking after deletion request for project uuid {project_uuid} ...")
                print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
                print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")

            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else False),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.entity_absent
            )
            if Auditor.DEBUG_VERBOSITY > 3:
                print(f"OK project uuid {project_uuid} seems deleted")

    @staticmethod
    def delete_project(host, key, project_name, version, wait=True, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_name is not None and project_name != "")
        assert (version is not None and version != "")

        if Auditor.DEBUG_VERBOSITY > 3:
            # Found UUID (if any) will be reported by the called method
            print(f"Querying for UUID of project to delete ('{project_name}' '{version}')...")
        project_uuid = Auditor.get_project_with_version_id(host, key, project_name, version, verify=verify)
        if project_uuid is None or len(project_uuid) < 1:
            if Auditor.DEBUG_VERBOSITY > 3:
                print(f"UUID of project to delete not found")
            return
        Auditor.delete_project_uuid(host, key, project_uuid, wait=wait, verify=verify)

    @staticmethod
    def get_issue_details(component):
        return {
            'cveid': component.get('vulnerability').get('vulnId'),
            'purl': component.get('component').get('purl'),
            'severity_level': component.get('vulnerability').get('severity')
        }

    @staticmethod
    def get_project_policy_violations(host, key, project_id, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + API_POLICY_VIOLATIONS % project_id
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get policy violations: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get policy violations", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def check_vulnerabilities(host, key, project_uuid, rules, show_details, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_uuid is not None and project_uuid != "")

        project_findings = Auditor.get_project_findings(host, key, project_uuid, verify=verify)
        severity_scores = Auditor.get_project_finding_severity(project_findings)
        print("severity_scores,  ",severity_scores)

        vuln_details = list(map(lambda f: Auditor.get_issue_details(f), project_findings))

        if show_details == 'TRUE' or show_details == 'ALL':
            for items in vuln_details:
                print(items)
# the condition for checking rules  i.e. -r critical:1:false,high:2:false,medium:10:false,low:10:false
        for rule in rules:
            severity, count, fail = rule.split(':')
            severity = severity.strip()
            count = count.strip()
            fail = fail.strip()

            #fail = True
            if fail == 'True' or fail == 'true':
                fail = 'True'
            # not failing by default
            else:
                fail = 'False'

            s_issue_count = severity_scores.get(severity.upper())

            if s_issue_count is None:
                continue
            if s_issue_count >= int(count):
                message = "Threshold for {severity_category} severity issues exceeded. Failing as per instructed rules (-r)".format(severity_category=severity.upper())
                if fail == 'True':
                    raise AuditorException(message)
                    print(message)
                else:
                    continue

        print('Vulnerability audit resulted in no violations.')

    @staticmethod
    def check_policy_violations(host, key, project_uuid, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_uuid is not None and project_uuid != "")

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
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + API_PROJECT_FINDING + '/{}'.format(project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get project findings: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get project findings", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_project_list(
            host, key,
            project_name=None,
            exclude_inactive=False,
            exclude_children=False,
            verify=True
    ):
        """ Return a list of dictionaries with basic information about
        all known projects (optionally constrained to one `project_name`),
        or raise exceptions upon errors.
        Further options are to exclude_inactive and/or exclude_children.
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_name is None or project_name != "")

        url = host + API_PROJECT
        urlsep = "?"
        if project_name is not None:
            url += "{}name={}".format(urlsep, project_name)
            urlsep = "&"

        if isinstance(exclude_inactive, bool):
            url += "{}excludeInactive={}".format(urlsep, exclude_inactive)
            urlsep = "&"

        # FIXME: As of DT 4.9.0 it seems the `onlyRoot=bool` handling is
        #  inverted vs. its documentation ("true" returns root and child
        #  projects, "false" returns only the root). If this gets fixed
        #  by upstream later (or behaved differently in other versions)
        #  we may want to query get_dependencytrack_version(), and maybe
        #  cache it for each "host", so we would only invert the boolean
        #  for some range of server versions...
        if isinstance(exclude_children, bool):
            url += "{}onlyRoot={}".format(urlsep, not exclude_children)
            #urlsep = "&"

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            raise AuditorRESTAPIException("Cannot get project list", r)
        return json.loads(r.text)

    @staticmethod
    def get_project_without_version_id(host, key, project_name, version, verify=True):
        """ Look up a particular project instance by name and version,
        querying for a list of all projects and filtering that.

        Returns project UUID or "" upon REST API request HTTP
        error states (may raise exceptions on other types of errors)
        or None if nothing was found (without errors).

        Please see whether the get_project_with_version_id() method
        works for you instead (should be less expensive computationally).
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_name is not None and project_name != "")
        assert (version is not None and version != "")

        try:
            response_dict = Auditor.get_project_list(host, key, verify=verify)
            for project in response_dict:
                if project_name == project.get('name') and project.get('version') == version:
                    _project_id = project.get('uuid')
                    return _project_id
            return None
        except AuditorRESTAPIException as ex:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get project '{project_name}' '{version}' without version id: {ex.result.status_code} {ex.result.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get project without version id", r)
            return ""

    @staticmethod
    def get_project_with_version_id(host, key, project_name, version, verify=True):
        """ Look up a particular project instance by name and version,
        using a dedicated REST API call for that purpose.

        Returns project UUID or "" empty string upon REST API request
        HTTP error states (may raise exceptions on other types of errors).
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_name is not None and project_name != "")
        assert (version is not None and version != "")

        project_name = project_name
        version = version
        url = host + API_PROJECT_LOOKUP + '?name={}&version={}'.format(project_name, version)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        res = requests.get(url, headers=headers, verify=verify)
        if res.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get project '{project_name}' '{version}' id: {res.status_code} {res.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get project id", res)
            return ""
        response_dict = json.loads(res.text)
        return response_dict.get('uuid')

    @staticmethod
    def read_bom_file(filename):
        """ Read original XML or JSON Bom file and re-encode it to DT server's liking. """
        assert (filename is not None and filename != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"Reading {filename} ...")
        filenameChecked = filename if Path(filename).exists() else str(Path(__file__).parent / filename)
        if filenameChecked != filename and Auditor.DEBUG_VERBOSITY > 2:
            print(f"Actually, resolved it as {filenameChecked} ...")

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
    def read_upload_bom(
        host, key,
        project_name, version, filename, auto_create,
        project_uuid=None,
        parent_project=None, parent_version=None, parent_uuid=None,
        wait=False, verify=True
    ):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (
            (project_name is not None and project_name != "" and
             version is not None and version != "") or
            (project_uuid is not None and project_uuid != ""))
        assert (filename is not None and filename != "")

        data = Auditor.read_bom_file(filename)

        if Auditor.DEBUG_VERBOSITY > 2:
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

        # These where added in version 4.8 of DT
        if parent_project:
            payload["parentName"] =  parent_project

        if parent_version:
            payload["parentVersion"] = parent_version

        if parent_uuid:
            payload["parentUUID"] = parent_uuid

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.put(host + API_BOM_UPLOAD, data=json.dumps(payload), headers=headers, verify=verify)
        if r.status_code != 200:
            raise AuditorRESTAPIException(f"Cannot upload {filename}", r)

        bom_token = json.loads(r.text).get('token')
        if bom_token and wait:
            Auditor.poll_bom_token_being_processed(host, key, bom_token, wait=wait, verify=verify)

        return bom_token

    @staticmethod
    def clone_project_by_uuid(
            host, key, old_project_version_uuid,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=False, verify=True, safeSleep=3
    ):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (old_project_version_uuid is not None and old_project_version_uuid != "")
        assert (new_version is not None and new_version != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"Cloning project+version entity {old_project_version_uuid} to new version {new_version}...")

        # Note that DT does not constrain the ability to assign arbitrary
        # values (which match the schema) to project name and version -
        # even if they seem to duplicate an existing entity. Project UUID
        # of each instance is what matters. Same-ness of names allows it
        # to group separate versions of the project.
        # UPDATE: Fixed in DT-4.9.0, see https://github.com/DependencyTrack/dependency-track/issues/2958
        payload = {
            "project":              "%s" % old_project_version_uuid,
            "version":              "%s" % new_version,
            "includeACL":           (includeACL if (includeACL is not None) else (includeALL is True)),
            "includeAuditHistory":  (includeAuditHistory if (includeAuditHistory is not None) else (includeALL is True)),
            "includeComponents":    (includeComponents if (includeComponents is not None) else (includeALL is True)),
            "includeProperties":    (includeProperties if (includeProperties is not None) else (includeALL is True)),
            "includeServices":      (includeServices if (includeServices is not None) else (includeALL is True)),
            "includeTags":          (includeTags if (includeTags is not None) else (includeALL is True))
        }
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.put(host + API_PROJECT_CLONE, data=json.dumps(payload), headers=headers, verify=verify)
        if Auditor.DEBUG_VERBOSITY > 3:
            print (f"Got response: {r}")
            print (f"Got text: {r.text}")
        if r.status_code != 200:
            if r.status_code > 500:
                if Auditor.DEBUG_VERBOSITY > 3:
                    print (f"Will wait and retry: {r}")
                time.sleep(5)
                r = requests.put(host + API_PROJECT_CLONE, data=json.dumps(payload), headers=headers, verify=verify)
                if Auditor.DEBUG_VERBOSITY > 3:
                    print (f"Got response: {r}")
                    print (f"Got text: {r.text}")

            if r.status_code != 200:
                raise AuditorRESTAPIException(f"Cannot clone {old_project_version_uuid}", r)

        new_project_uuid = None
        if r.text is not None:
            try:
                new_project_uuid = json.loads(r.text).get('uuid')
            except Exception as ignored:
                pass

        # Per dev-testing with DT 4.9.0, clone() takes non-trivial time
        # on the backend API server even after the UUID is assigned -
        # some further operations take place. Only when everything is
        # quiet it is safe to proceed with delete/rename/... operations.
        # Maybe DT 4.10+ would fix this - in discussion.
        if safeSleep is not None:
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Sleeping {safeSleep} sec after cloning project {old_project_version_uuid} ...")
            time.sleep(safeSleep)

        old_project_obj = None
        if new_project_uuid is None or new_project_uuid == "":
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Querying known projects to identify the new clone ...")
            try:
                # First get details (e.g. name) of the old project we cloned from:
                old_project_obj = Auditor.poll_project_uuid(
                    host, key, old_project_version_uuid, wait=wait, verify=verify)
                if old_project_obj is None or not isinstance(old_project_obj, dict):
                    if Auditor.DEBUG_VERBOSITY > 2:
                        print(f"Failed to query the old project details")
                else:
                    new_project_uuid = Auditor.get_project_with_version_id(
                        host, key, old_project_obj.get("name"), new_version, verify=verify)
                    if new_project_uuid is not None and len(new_project_uuid) > 0:
                        if Auditor.DEBUG_VERBOSITY > 2:
                            print("Query identified the new clone of %s ('%s' version '%s' => '%s') as %s" % (
                                old_project_version_uuid,
                                old_project_obj.get("name"), old_project_obj.get("version"),
                                new_version, new_project_uuid))
            except Exception as ex:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Failed to query known projects to identify the new clone: {ex}")
                pass

        if new_project_uuid is not None and len(new_project_uuid) > 0 and wait:
            Auditor.poll_project_uuid(host, key, new_project_uuid, wait=wait, verify=verify)

        if new_name is not None and len(new_name) > 0 and (old_project_obj is None or old_project_obj.get("name") != new_name):
            if new_project_uuid is None:
                raise AuditorException(f"Cannot rename cloned project: new UUID not discovered yet")
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Renaming cloned project+version entity {new_project_uuid} to new name {new_name} with version {new_version}...")
            r = requests.patch(
                host + API_PROJECT + '/{}'.format(new_project_uuid),
                data=json.dumps({"name": "%s" % new_name}),
                headers=headers, verify=verify)
            if r.status_code != 200:
                if r.status_code == 304:
                    if Auditor.DEBUG_VERBOSITY > 2:
                        print("Not renaming cloned project: same as before")
                else:
                    raise AuditorRESTAPIException(f"Cannot rename {new_project_uuid}", r)

        return new_project_uuid

    @staticmethod
    def clone_project_by_name_version(
            host, key, old_project_name, old_project_version,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=False, verify=True, safeSleep=3
    ):
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (old_project_name is not None and old_project_name != "")
        assert (old_project_version is not None and old_project_version != "")
        assert (new_version is not None and new_version != "")

        old_project_version_uuid =\
            Auditor.get_project_with_version_id(host, key, old_project_name, old_project_version, verify)
        assert (old_project_version_uuid is not None and old_project_version_uuid != "")
        return Auditor.clone_project_by_uuid(
            host, key, old_project_version_uuid,
            new_version, new_name, includeALL,
            includeACL, includeAuditHistory,
            includeComponents, includeProperties,
            includeServices, includeTags,
            wait, verify, safeSleep)

    @staticmethod
    def set_project_active(host, key, project_id, active=True, wait=False, verify=True):
        """ Requires PORTFOLIO_MANAGEMENT permission. """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        payload = {
            "uuid": project_id,
            "active": active
        }

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = requests.patch(
            host + API_PROJECT + '/{}'.format(project_id),
            data=json.dumps(payload), headers=headers, verify=verify)
        if r.status_code != 200:
            if r.status_code == 304:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Not changing 'active' status of project to '{active}': it is same as before")
            else:
                raise AuditorRESTAPIException(f"Cannot modify project {project_id}", r)

        while wait:
            objPrj = Auditor.poll_project_uuid(host, key, project_id, wait=wait, verify=verify)
            if objPrj is not None and active == objPrj.get("active"):
                wait = False

    @staticmethod
    def clone_update_project(
            host, key, filename, new_version,
            new_name=None,
            old_project_version_uuid=None,
            old_project_name=None, old_project_version=None,
            activate_old=None, activate_new=None,
            deleteExistingClone=False,
            parent_project=None, parent_version=None, parent_uuid=None,
            includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            wait=True, verify=True, safeSleep=3
    ):
        """
        Clones an existing project and uploads a new SBOM document into it, in one swift operation.

        TODO: Parse Bom.Metadata.Component if present (XML, JSON) to get fallback name and/or version.
        """
        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert ((old_project_version_uuid is not None and old_project_version_uuid != "") or
                (old_project_name is not None and old_project_version is not None and
                 old_project_name != "" and old_project_version != ""
                 ))
        assert (filename is not None and filename != "")

        # NOTE: name+version are ignored if a UUID is provided
        if old_project_version_uuid is None:
            old_project_version_uuid = \
                Auditor.get_project_with_version_id(host, key, old_project_name, old_project_version, verify)

        assert (old_project_version_uuid is not None and old_project_version_uuid != "")
        old_project_obj = Auditor.poll_project_uuid(
            host, key, old_project_version_uuid, wait=wait, verify=verify)

        if new_name is None:
            new_name = old_project_obj.get("name")
            if old_project_name is not None and new_name != old_project_name:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print(f"WARNING: caller says old_project_name={old_project_name} but REST API metadata for " +
                          f"UUID {old_project_version_uuid} says the name is actually {new_name} (using the latter)")

        # Avoid fatal exceptions here, if e.g. old target
        # clone does not exist and can not be deleted:
        fatalException = AuditorException.INSTANT_EXIT
        AuditorException.INSTANT_EXIT = False
        if deleteExistingClone:
            try:
                # NOTE: Here we insist on at least some wait (True or seconds-count)
                # for completion of the call before proceeding
                Auditor.delete_project(
                    host, key, new_name, new_version,
                    wait=(wait if wait is not None and wait is not False else True),
                    verify=verify)
            except Exception as ignored:
                pass

        # NOTE: Here we insist on at least some wait (True or seconds-count)
        # for completion of the call before proceeding; defaults to 4 min as
        # if a TCP timeout.
        try:
            new_project_uuid = Auditor.clone_project_by_uuid(
                host, key, old_project_version_uuid,
                new_version, new_name, includeALL,
                includeACL, includeAuditHistory,
                includeComponents, includeProperties,
                includeServices, includeTags,
                wait=(wait if wait is not None and wait is not False else 240),
                verify=verify, safeSleep=safeSleep)
        except AuditorRESTAPIException as ex:
            # Is there a name collision? For example, if we clone a project
            # (always initially using an old name) and a version intended
            # for the new name which *also* exists in the original project:
            if ex.result.status_code != 409 or new_name == old_project_obj.get("name"):
                # Not a conflict error but something else, or not
                # avoidable by "cheap tricks" anyway - so rethrow
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Failed to clone: {ex}")
                raise ex

            # If here: HTTP-409 (Conflict) and different names
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Failed to clone due to version-value conflict, will retry with intermediate random version value: {ex}")

            # Use a somewhat random "version" - plant UUID there temporarily:
            new_project_uuid = Auditor.clone_project_by_uuid(
                host, key, old_project_version_uuid,
                old_project_version_uuid, new_name, includeALL,
                includeACL, includeAuditHistory,
                includeComponents, includeProperties,
                includeServices, includeTags,
                wait=(wait if wait is not None and wait is not False else 240),
                verify=verify, safeSleep=safeSleep)
            headers = {
                "content-type": "application/json",
                "X-API-Key": key
            }
            r = requests.patch(
                host + API_PROJECT + '/{}'.format(new_project_uuid),
                data=json.dumps({"version": "%s" % new_version}),
                headers=headers, verify=verify)
            if r.status_code != 200:
                raise AuditorRESTAPIException(f"Cannot patch {new_project_uuid} version", r)

            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Completed the workaround with intermediate version value")

        AuditorException.INSTANT_EXIT = fatalException

        assert (new_project_uuid is not None and new_project_uuid != "")

        bom_token = Auditor.read_upload_bom(
            host, key, project_name=None, version=None,
            filename=filename, auto_create=False, project_uuid=new_project_uuid,
            parent_project=parent_project, parent_version=parent_version, parent_uuid=parent_uuid,
            wait=wait, verify=verify)

        assert (bom_token is not None and bom_token != "")

        if activate_old is not None:
            if Auditor.DEBUG_VERBOSITY > 2:
                print("%sctivating original project %s ..." % ("A" if activate_old else "Dea", old_project_version_uuid))
            Auditor.set_project_active(host, key, old_project_version_uuid, activate_old, wait=wait, verify=verify)

        if activate_new is not None:
            if Auditor.DEBUG_VERBOSITY > 2:
                print("%sctivating cloned project %s ..." % ("A" if activate_new else "Dea", new_project_uuid))
            Auditor.set_project_active(host, key, new_project_uuid, activate_new, wait=wait, verify=verify)

        return new_project_uuid

    @staticmethod
    def get_dependencytrack_version(host, key, verify=True):
        assert (host is not None and host != "")
        assert (key is not None and key != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print("getting version of OWASP DependencyTrack")
            print(host, key)

        url = host + API_VERSION
        headers = {
            "content-type": "application/json",
            "X-API-Key": key.strip()
        }
        if Auditor.DEBUG_VERBOSITY > 2:
            print(url)
        res = requests.get(url, headers=headers, verify=verify)
        if res.status_code != 200:
            print(f"Cannot connect to the server {res.status_code} {res.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot connect to the server", res)
            return ""
        response_dict = json.loads(res.text)
        if Auditor.DEBUG_VERBOSITY > 2:
            print(response_dict)
        return response_dict
