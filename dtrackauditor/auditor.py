import os
import sys
import json
import time
import base64
import inspect
import polling
import requests
from pathlib import Path

# On your Dependency-Track instance you can open its $ROOTURL/api/swagger.json
# to see the currently defined endpoints and their query parameters and other
# details. For JSON payload data types (referenced from Swagger spec) see the
# respective CycloneDX spec version, e.g. https://cyclonedx.org/docs/1.4/json/

API_PROJECT = '/api/v1/project'
API_PROJECT_CLONE = '/api/v1/project/clone'
API_PROJECT_LOOKUP = '/api/v1/project/lookup'
API_PROJECT_FINDING = '/api/v1/finding/project/%s'
API_PROJECT_FINDING_EXPORT = '/api/v1/finding/project/%s/export'
API_PROJECT_FINDING_REANALYZE = '/api/v1/finding/project/%s/analyze'
API_PROJECT_METRICS_REFRESH = '/api/v1/metrics/project/%s/refresh'
API_COMPONENT_METRICS_REFRESH = '/api/v1/metrics/component/%s/refresh'
API_PORTFOLIO_METRICS_REFRESH = '/api/v1/metrics/portfolio/%s/refresh'
API_PROJECT_PROPERTIES = '/api/v1/project/%s/property'
API_PROJECT_COMPONENTS = '/api/v1/component/project/%s'
API_COMPONENT = '/api/v1/component'
API_COMPONENT_GRAPH_IN_PROJECT = '/api/v1/component/%s/dependencyGraph/%s'
API_COMPONENT_DEPENDENCIES = '/api/v1/dependencyGraph/component/%s/directDependencies'
API_PROJECT_DEPENDENCIES = '/api/v1/dependencyGraph/project/%s/directDependencies'
API_BOM_UPLOAD = '/api/v1/bom'
API_BOM_TOKEN = '/api/v1/bom/token'
API_EVENT_TOKEN = '/api/v1/event/token'
API_POLICY_VIOLATIONS = '/api/v1/violation/project/%s'
API_ANALYSIS_VULNERABILITY = '/api/v1/analysis'
API_ANALYSIS_POLICY_VIOLATION = '/api/v1/violation/analysis'
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

    def __init__(
            self,
            base_url: str|None = None,
            api_key: str|None = None,
            ssl_verify: str|bool|None = None,
            auto_close_request_sessions: bool | None = None
    ):
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

        self.auto_close_request_sessions: bool|None = auto_close_request_sessions
        """ Call close_request_session() after each wrapped operation?

        Use e.g. if suspecting that this is behind "too many open files").

        Note that normally we do not auto-close them and may benefit from server/client support
        of multiple queries per TCP session, etc..
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

    def close_request_session(self, catchExceptions=True):
        # Not making this a static method, in case we would
        # eventually explicitly provide "requests.session()"
        # objects for a client and the calls it makes.
        Auditor.close_request_session(catchExceptions)

    def auto_close_request_session(self, catchExceptions=True):
        """ Primarily intended for internal use, to optionally
        close HTTP connections (see auto_close_request_sessions
        property) after completing the wrapped Dependency-Track
        operations.

        Hopefully this keeps the requests.session() involved in
        closer step-lock with the session actually used for those
        preceding queries that we would now try to close.
        """

        # None is effectively False, for least surprise and backwards
        # compatibility. It is not reported in stringification however.
        if self.auto_close_request_sessions is not None and self.auto_close_request_sessions:
            self.close_request_session(catchExceptions)

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
            ssl_verify_default: str|None = None,
            auto_close_request_session_varname: str|None = 'DTRACK_CLIENT_AUTO_CLOSE_REQUEST_SESSION',
            auto_close_request_session_default: str|None = None
    ): # -> DTrackClient:
        """ (Re-)initialize settings from environment variables whose names
        are specified by arguments, with optional fallback default values.
        You can specify something_varname=None to avoid (re-)setting that value.
        """
        if base_url_varname is not None:
            self.base_url = os.environ.get(base_url_varname, base_url_default)
            if self.base_url is None or len(self.base_url) == 0:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print("Auditor.initByEnvvars(): WARNING: no URL found via envvar '%s'" % base_url_varname)

        if api_key_varname is not None:
            self.api_key = os.environ.get(api_key_varname, api_key_default)
            if (self.api_key is None or len(self.api_key) == 0) and Auditor.DEBUG_VERBOSITY > 0:
                print("Auditor.initByEnvvars(): WARNING: no API Key found via envvar '%s'" % api_key_varname)

        if ssl_verify_varname is not None:
            self.ssl_verify = os.environ.get(ssl_verify_varname, ssl_verify_default)
            if self.ssl_verify is None or len(self.ssl_verify) == 0:
                if Auditor.DEBUG_VERBOSITY > 0 and str(self.base_url).lower().startswith('https://'):
                    print("Auditor.initByEnvvars(): WARNING: no explicit verification toggle or cert chain found via envvar '%s'" % ssl_verify_varname)

        # For self.auto_close_request_session():
        if auto_close_request_session_varname is not None:
            s = os.environ.get(auto_close_request_session_varname, auto_close_request_session_default)
            if s is None or len(s) == 0:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print("Auditor.initByEnvvars(): WARNING: no explicit setting for auto-closing of HTTP sessions found via envvar '%s'" % auto_close_request_session_varname)
                # Use defaults
                self.auto_close_request_sessions = None
            else:
                sl = str(s).lower()
                if sl in ["false", "no", "off", "0"]:
                    self.auto_close_request_sessions = False
                elif sl in ["true", "yes", "on", "1"]:
                    self.auto_close_request_sessions = True
                else:
                    if Auditor.DEBUG_VERBOSITY > 0:
                        print("Auditor.initByEnvvars(): WARNING: unsupported setting for auto-closing of HTTP sessions found via envvar '%s': %s" % (auto_close_request_session_varname, s))
                    # Use defaults
                    self.auto_close_request_sessions = None

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
        return "DTrackClient instance for '%s' identified by '%s'; SSL/TLS verification: %s%s" % (
            str(self.base_url), str(self.api_key), str(self.ssl_verify),
            ("" if self.auto_close_request_sessions is None else (";%s auto-closing request sessions" % ("" if self.auto_close_request_sessions else " NOT")))
        )

    def poll_bom_token_being_processed(self, bom_token, wait=True):
        retval = Auditor.poll_bom_token_being_processed(
            host=self.base_url, key=self.api_key,
            bom_token=bom_token,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def poll_event_token_being_processed(self, bom_token, wait=True):
        retval = Auditor.poll_event_token_being_processed(
            host=self.base_url, key=self.api_key,
            bom_token=bom_token,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def poll_project_uuid(self, project_id, wait=True):
        retval = Auditor.poll_project_uuid(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def delete_project_uuid(self, project_id, wait=True):
        retval = Auditor.delete_project_uuid(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def delete_project(self, project_name, wait=True):
        retval = Auditor.delete_project(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_policy_violations(self, project_id):
        retval = Auditor.get_project_policy_violations(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def check_vulnerabilities(self, project_id, rules, show_details):
        retval = Auditor.check_vulnerabilities(
            host=self.base_url, key=self.api_key,
            project_uuid=project_id,
            rules=rules,
            show_details=show_details,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def check_policy_violations(self, project_id):
        try:
            Auditor.check_policy_violations(
                host=self.base_url, key=self.api_key,
                project_id=project_id,
                verify=self.ssl_verify)
        except Exception as retval:
            self.auto_close_request_session()
            raise retval

    def get_project_findings(self, project_id):
        retval = Auditor.get_project_findings(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_findings_export(self, project_id):
        retval = Auditor.get_project_findings_export(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def request_project_findings_reanalyze(self, project_id, wait=False):
        retval = Auditor.request_project_findings_reanalyze(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            wait=wait,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def request_project_metrics_refresh(self, project_id, wait=False):
        retval = Auditor.request_project_metrics_refresh(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            wait=wait,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def request_component_metrics_refresh(self, component_id, wait=False):
        retval = Auditor.request_component_metrics_refresh(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            wait=wait,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def request_portfolio_metrics_refresh(self, portfolio_id, wait=False):
        retval = Auditor.request_portfolio_metrics_refresh(
            host=self.base_url, key=self.api_key,
            portfolio_id=portfolio_id,
            wait=wait,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_component_vulnerability_analysis(self, component_id, vulnerability_id):
        retval = Auditor.get_component_vulnerability_analysis(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            vulnerability_id=vulnerability_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_component_violation_analysis(self, component_id, violation_id):
        retval = Auditor.get_component_violation_analysis(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            violation_id=violation_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_component(self, component_id, includeRepositoryMetaData=None):
        retval = Auditor.get_component(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            includeRepositoryMetaData=includeRepositoryMetaData,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_component_graph_in_project(self, component_id, project_id):
        retval = Auditor.get_component_graph_in_project(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_component_dependencies(self, component_id):
        retval = Auditor.get_component_dependencies(
            host=self.base_url, key=self.api_key,
            component_id=component_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_dependencies(self, project_id):
        retval = Auditor.get_project_dependencies(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_components_list(
            self,
            project_id,
            only_outdated=False,
            only_direct=False
    ):
        retval = Auditor.get_project_components_list(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            only_outdated=only_outdated,
            only_direct=only_direct,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_properties_list(
            self,
            project_id
    ):
        retval = Auditor.get_project_properties_list(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_list(
            self,
            project_name=None,
            exclude_inactive=False,
            exclude_children=False
    ):
        retval = Auditor.get_project_list(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            exclude_inactive=exclude_inactive,
            exclude_children=exclude_children,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_without_version_id(self, project_name, version):
        retval = Auditor.get_project_without_version_id(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            version=version,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_project_with_version_id(self, project_name, version):
        retval = Auditor.get_project_with_version_id(
            host=self.base_url, key=self.api_key,
            project_name=project_name,
            version=version,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def read_upload_bom(
            self,
            project_name, version, filename, auto_create,
            project_id=None,
            parent_project=None, parent_version=None, parent_id=None,
            wait=True
    ):
        retval = Auditor.read_upload_bom(
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
        self.auto_close_request_session()
        return retval

    def clone_project_by_uuid(
            self, old_project_version_id,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            includePolicyViolations=None,
            makeCloneLatest=None,
            wait=True, safeSleep=3
    ):
        retval = Auditor.clone_project_by_uuid(
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
            includePolicyViolations=includePolicyViolations,
            makeCloneLatest=makeCloneLatest,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def clone_project_by_name_version(
            self, old_project_name, old_project_version,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            includePolicyViolations=None,
            makeCloneLatest=None,
            wait=True, safeSleep=3
    ):
        retval = Auditor.clone_project_by_name_version(
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
            includePolicyViolations=includePolicyViolations,
            makeCloneLatest=makeCloneLatest,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def set_project_active(self, project_id, active=True, wait=False):
        retval = Auditor.set_project_active(
            host=self.base_url, key=self.api_key,
            project_id=project_id,
            active=active,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

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
            includePolicyViolations=None,
            makeCloneLatest=None,
            uploadIntoClone=True,
            wait=True, safeSleep=3
    ):
        retval = Auditor.clone_update_project(
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
            includePolicyViolations=includePolicyViolations,
            makeCloneLatest=makeCloneLatest,
            uploadIntoClone=uploadIntoClone,
            safeSleep=safeSleep,
            wait=wait, verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval

    def get_dependencytrack_version(self):
        retval = Auditor.get_dependencytrack_version(
            host=self.base_url, key=self.api_key,
            verify=self.ssl_verify)
        self.auto_close_request_session()
        return retval


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

    cached_dependencytrack_versions = {}
    """
    Dict to store each tried host's last returned details from the
    get_dependencytrack_version() method. Maps string to further dict.

    May be used to fence calls added in recent DT releases,
    to avoid setting unsupported parameters to older REST API.
    """

    @staticmethod
    def get_paginated(url, headers, verify=True):
        """ Get a response from paginated API calls.

        Note this normally returns a "requests.Response" object, if the
        reply was short (whether successful or not), except when we had
        to go query the API page by page and ended up with the result
        of JSON parsing (normally a list) if all pages were HTTP-200.

        See also:

        * https://github.com/DependencyTrack/dependency-track/issues/209
        * https://github.com/DependencyTrack/dependency-track/discussions/1851
        * https://github.com/DependencyTrack/dependency-track/pull/3625
        """
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            return r

        try:
            if "X-Total-Count" not in r.headers:
                return r
        except Exception as ignored:
            # Not a dict or rather CaseInsensitiveDict
            return r

        # This endpoint supports pagination
        total_count = -1
        try:
            total_count = int(r.headers["X-Total-Count"])
        except ValueError as ignored:
            return r

        if total_count < 100:
            # Default page size is 100
            return r

        try:
            obj = json.loads(r.text)
            if len(obj) == total_count:
                return obj
        except Exception as ignored:
            pass

        if "?" in url:
            paged_url_base = url + "&"
        else:
            paged_url_base = url + "?"

        # Luckily, we can usually tell the server to give us all the
        # tens of thousands of answers in one go:
        paged_url = paged_url_base + "page=1&limit={}".format(total_count)
        r = requests.get(paged_url, headers=headers, verify=verify)
        if r.status_code == 200:
            return r

        # ...but if not - gotta really loop page by page and return
        # directly the JSON object as we can not set or replace a
        # "response.text" attribute value. Note that each DT REST API
        # page returns a complete valid JSON list with some "limit"
        # entries in it. We should not concatenate the raw strings!
        # And that this is often slower than getting one big reply,
        # so we at least try with larger pages!..
        obj = []
        n = 0
        pagesize = 1000
        while n * pagesize < total_count:
            # 1-based count
            n = n + 1
            paged_url = paged_url_base + "page={}&limit={}".format(n, pagesize)
            r = requests.get(paged_url, headers=headers, verify=verify)
            if r.status_code != 200:
                return r
            pageobj = json.loads(r.text)
            obj.extend(pageobj)
            if len(pageobj) < pagesize:
                break
            if len(obj) >= total_count:
                break

        return obj

    @staticmethod
    def checker_not_processing(response):
        """ Returns a success if specifically the request successfully (HTTP-200)
        returned a JSON object with a "processing" keyed entry, and its value is
        "false" (no processing currently happens for a query, typically by token).

        Used as a helper in polling.poll() as the check_success argument.
        """

        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("checker_not_processing()", response))
        if response.status_code != 200:
            return False
        status = json.loads(response.text).get('processing')
        return (status == False)

    @staticmethod
    def checker_uuid_present(response):
        """ Returns a success if specifically the request successfully (HTTP-200)
        returned a JSON object with an "uuid" keyed entry, and its value is non-trivial.

        Used as a helper in polling.poll() as the check_success argument.
        """

        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("checker_uuid_present()", response))
        if response.status_code != 200:
            return False
        uuid = json.loads(response.text).get('uuid')
        return (uuid is not None and len(uuid) > 0)

    @staticmethod
    def checker_entity_absent(response):
        """ Returns a success if specifically the request returned HTTP-404.

        Used as a helper in polling.poll() as the check_success argument.
        """

        if Auditor.DEBUG_VERBOSITY > 3:
            print(AuditorRESTAPIException.stringify("checker_entity_absent()", response))
        if response.status_code == 404:
            return True
        return False

    @staticmethod
    def poll_bom_token_being_processed(host, key, bom_token, wait=True, verify=True):
        """ FROM SWAGGER DOC:

        Determines if there are any tasks associated with the token that are
        being processed, or in the queue to be processed. This endpoint is
        intended to be used in conjunction with uploading a supported BOM
        document.

        Upon upload, a token will be returned. The token can then be queried
        using this endpoint to determine if any tasks (such as vulnerability
        analysis) is being performed on the BOM:

        * A value of <code>true</code> indicates processing is occurring.
        * A value of <code>false</code> indicates that no processing is
          occurring for the specified token.

        However, a value of <code>false</code> also does not confirm the
        token is valid, only that no processing is associated with the
        specified token.

        Requires permission <strong>BOM_UPLOAD</strong>

        Deprecated. Use <code>/v1/event/token/{uuid}</code> instead.
        See poll_event_token_being_processed() for the more generic call.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (bom_token is not None and bom_token != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print("Waiting for bom to be processed on dt server ...")
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"Processing bom token uuid is {bom_token}")
        url = host + API_BOM_TOKEN+'/{}'.format(bom_token)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
            print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")
        # NOTE: poll_forever!=False, ever!
        if wait:
            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else None),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.checker_not_processing
            )
        else:
            result = requests.get(url, headers=headers, verify=verify)
        return json.loads(result.text).get('processing')

    @staticmethod
    def poll_event_token_being_processed(host, key, event_token, wait=True, verify=True):
        """ FROM SWAGGER DOC:

        Determines if there are any tasks associated with the token that are
        being processed, or in the queue to be processed. This endpoint is
        intended to be used in conjunction with other API calls which return
        a token for asynchronous tasks (including BOM upload, which has its
        own deprecated similar endpoint).

        The token can then be queried using this endpoint to determine if the
        task is complete:

        * A value of <code>true</code> indicates processing is occurring.
        * A value of <code>false</code> indicates that no processing is
          occurring for the specified token.

        However, a value of <code>false</code> also does not confirm the
        token is valid, only that no processing is associated with the
        specified token.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (event_token is not None and bom_token != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print("Waiting for an async event to be processed on dt server ...")
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"Processing event token uuid is {event_token}")
        url = host + API_EVENT_TOKEN+'/{}'.format(event_token)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
            print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")
        # NOTE: poll_forever!=False, ever!
        if wait:
            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else None),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.checker_not_processing
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
        if Auditor.DEBUG_VERBOSITY > 3:
            print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
            print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")
        # NOTE: poll_forever!=False, ever!
        if wait:
            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else None),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.checker_uuid_present
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
                try:
                    return json.loads(result.text)
                except Exception as ignored:
                    return None
            else:
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Deletion request for project uuid {project_uuid} failed: {result.status_code} {result.reason} => {result.text}")
                # TODO? raise AuditorRESTAPIException(f"Deletion request for project uuid {project_uuid} failed, r)

        if wait:
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"Checking after deletion request for project uuid {project_uuid} ...")
            if Auditor.DEBUG_VERBOSITY > 3:
                print(f"poll_forever={(wait if isinstance(wait, bool) else False)}")
                print(f"timeout={(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None)}")

            result = polling.poll(
                lambda: requests.get(url, headers=headers, verify=verify),
                step=5,
                poll_forever=(wait if isinstance(wait, bool) else False),
                timeout=(wait if (isinstance(wait, (int, float)) and not isinstance(wait, bool)) else None), # raises polling.TimeoutException
                check_success=Auditor.checker_entity_absent
            )
            if Auditor.DEBUG_VERBOSITY > 3:
                print(f"OK project uuid {project_uuid} seems deleted")

        try:
            return json.loads(result.text)
        except Exception as ignored:
            # Something is null, not JSON, etc.
            return None

    @staticmethod
    def delete_project(host, key, project_name, version, wait=True, verify=True):
        """ Deletes a project instance by specified name and version. """

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
            return None
        return Auditor.delete_project_uuid(host, key, project_uuid, wait=wait, verify=verify)

    @staticmethod
    def get_issue_details(component):
        """ Picks out specific details about a vulnerability associated with
        a component, returns a dict with keys: "cveid", "purl", "severity_level".

        Used as a helper in check_vulnerabilities() method.
        """

        return {
            'cveid': component.get('vulnerability').get('vulnId'),
            'purl': component.get('component').get('purl'),
            'severity_level': component.get('vulnerability').get('severity')
        }

    @staticmethod
    def get_project_policy_violations(host, key, project_id, verify=True):
        """ Returns a list of policy violations (license etc.) associated with
        a project instance. """

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
        """ Legacy of the single-purpose command-line tool :)

        Check if a project instance has associated vulnerabilities, and
        if their hit-counts under different categories are within ranges
        specified by "rules" conditions. If specified thresholds are
        exceeded, an AuditorException is raised with the detail message.

        :param rules:   A list of strings, each with a colon-separated
                        "severity:count:fail" payload. The "fail" part
                        may be "true" to require failing this check if
                        the threshold is exceeded.
                        NOTE: In the command-line tool this list is
                        split from a single comma-separated argument like:
                        -r critical:1:false,high:2:false,medium:10:false,low:10:false

        :param show_details:    "TRUE" or "ALL" to print out vulnerability details
        """

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

        # the condition for checking rules, i.e.
        #   -r critical:1:false,high:2:false,medium:10:false,low:10:false
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
        """ Legacy of the single-purpose command-line tool :)

        Check if there are any policy violations. Prints a message and
        returns if none, or prints details and raises an AuditorException
        if the count is non-zero.
        """

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
        """ Accounts severities of each vulnerability associated with all
        components in a project, returns a dict with keys: "CRITICAL",
        "HIGH", "MEDIUM", "LOW", "UNASSIGNED".

        Used as a helper in check_vulnerabilities() method.
        """

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
    def get_project_findings(host, key, project_id, suppressed=None, verify=True):
        """ Get findings (vulnerability reports) about a project. """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + (API_PROJECT_FINDING % project_id)
        if suppressed is True:
            url = url + "?suppressed=true"
        elif suppressed is False:
            url = url + "?suppressed=false"
        # else server default
        # NOTE: seems to have no effect IRL

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
    def get_project_findings_export(host, key, project_id, verify=True):
        """ Get findings (vulnerability reports) about a project.

        Note: get_project_findings_export() gives similar info to
        that from get_project_findings(), just encased deeper into
        another structure (also has project metadata) and differently
        represented timestamps (string vs number). It also does
        not have parameters like "source" and "suppressed" and
        supposedly reports everything there is to know.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + (API_PROJECT_FINDING_EXPORT % project_id)
        # Note: export has no parameters, such as "suppressed"
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot export project findings: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot export project findings", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def request_project_findings_reanalyze(host, key, project_id, wait=False, verify=True):
        """
        Async operation to refresh vulnerability analysis of a project
        version. The REST API endpoint returns an operation token which
        we can poll for to see if it completed if "wait" == True. The
        token is returned anyway in case of success.

        NOTE: This operation should not normally be needed with "active"
        project instances (names+versions), since Dependency-Track server
        re-scans them regularly, but it may be useful with "not-active"
        historic ones.

        In current DT Web-UI, this corresponds to "Reanalyze" button on
        the "Audit Vulnerabilities" tab. Note that this differs from the
        refresh button on the "Overview" tab which just re-evaluates the
        metrics of a project (see request_project_metrics_refresh() for
        that action).

        There does not seem to be an equivalent for policy violations.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + (API_PROJECT_FINDING_REANALYZE % project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = requests.post(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot request re-analysis of project findings: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot request re-analysis of project findings", r)
            return {}

        event_token = json.loads(r.text).get('token')
        if event_token and wait:
            Auditor.poll_event_token_being_processed(host, key, event_token, wait=wait, verify=verify)

        return event_token

    @staticmethod
    def request_project_metrics_refresh(host, key, project_id, wait=False, verify=True):
        """
        Async operation to refresh metrics (e.g. component, vulnerability
        and policy alert counts) of a project instance (name+version) by
        its UUID. The REST API endpoint returns an HTTP code and empty
        document, so there is currently nothing to actually "wait" for.
        The method currently returns True if query yielded HTTP-200, or
        False otherwise.

        NOTE: This operation should not normally be needed with "active"
        project instances (names+versions), since Dependency-Track server
        re-scans them regularly, but it may be useful with "not-active"
        historic ones.

        In current DT Web-UI, this corresponds to the refresh button on
        the "Overview" tab which re-evaluates the metrics of a project.
        Note that this differs from the "Reanalyze" button on the "Audit
        Vulnerabilities" tab which actively compares known vulnerabilities
        to component metadata (see request_project_findings_reanalyze()
        for that action).

        Requires permission <strong>PORTFOLIO_MANAGEMENT</strong>
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + (API_PROJECT_METRICS_REFRESH % project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot request refresh of project metrics: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot request refresh of project metrics", r)
            return False

        return True

    @staticmethod
    def request_component_metrics_refresh(host, key, component_id, wait=False, verify=True):
        """
        Async operation to refresh component metrics (e.g. vulnerability
        and policy alert counts).

        The method currently returns True if query yielded HTTP-200, or
        False otherwise.

        Requires permission <strong>PORTFOLIO_MANAGEMENT</strong>
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")

        url = host + (API_COMPONENT_METRICS_REFRESH % component_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot request refresh of component metrics: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot request refresh of component metrics", r)
            return False

        return True

    @staticmethod
    def request_portfolio_metrics_refresh(host, key, portfolio_id, wait=False, verify=True):
        """
        Async operation to refresh portfolio metrics (e.g. project,
        component, vulnerability and policy alert counts).

        The method currently returns True if query yielded HTTP-200,
        or False otherwise.

        Requires permission <strong>PORTFOLIO_MANAGEMENT</strong>
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (portfolio_id is not None and portfolio_id != "")

        url = host + (API_PORTFOLIO_METRICS_REFRESH % portfolio_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot request refresh of portfolio metrics: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot request refresh of portfolio metrics", r)
            return False

        return True

    @staticmethod
    def get_component_vulnerability_analysis(host, key, component_id, vulnerability_id, verify=True):
        """ Get detailed information about a specific vulnerability analysis
        of a specific component by their IDs. """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")
        assert (vulnerability_id is not None and vulnerability_id != "")

        url = host + API_ANALYSIS_VULNERABILITY + ("?component=%s&vulnerability=%s"% (component_id, vulnerability_id))
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component vulnerability analysis: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component vulnerability analysis", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_component_violation_analysis(host, key, component_id, violation_id, verify=True):
        """ Get detailed information about a specific policy violation
        analysis of a specific component by their IDs. """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")
        assert (violation_id is not None and violation_id != "")

        url = host + API_ANALYSIS_POLICY_VIOLATION + ("?component=%s&policyViolation=%s"% (component_id, violation_id))
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component policy violation analysis: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component policy violation analysis", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_component(host, key, component_id, includeRepositoryMetaData=None, verify=True):
        """ Get detailed information about a component. """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")

        url = host + API_COMPONENT + "/{}".format(component_id)
        if includeRepositoryMetaData is True:
            url = url + "?includeRepositoryMetaData=true"
        elif includeRepositoryMetaData is False:
            url = url + "?includeRepositoryMetaData=false"
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component info: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component info", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_component_graph_in_project(host, key, component_id, project_id, verify=True):
        """ FROM SWAGGER DOC:

        Returns the expanded dependency graph to every occurrence of a component.

        Requires permission <strong>VIEW_PORTFOLIO</strong>.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")
        assert (project_id is not None and project_id != "")

        url = host + API_COMPONENT_GRAPH_IN_PROJECT % (project_id, component_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component graph info: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component graph info", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_component_dependencies(host, key, component_id, verify=True):
        """ FROM SWAGGER DOC:

        Returns a list of specific components and services from component UUID.

        Requires permission <strong>VIEW_PORTFOLIO</strong>.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (component_id is not None and component_id != "")

        url = host + API_COMPONENT_DEPENDENCIES % (component_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component graph info: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component graph info", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_project_dependencies(host, key, project_id, verify=True):
        """ FROM SWAGGER DOC:

        Returns a list of specific components and services from project UUID.

        Requires permission <strong>VIEW_PORTFOLIO</strong>.

        NOTE: This information should also be available from initial project
        lookup, as a string 'dependencies' with JSON in it.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + API_PROJECT_DEPENDENCIES % (project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get component graph info: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get component graph info", r)
            return {}
        return json.loads(r.text)

    @staticmethod
    def get_project_components_list(
            host, key,
            project_id,
            only_outdated=False,
            only_direct=False,
            verify=True
    ):
        """
        Get a list of components that comprise the specified project.

        Optionally constrain to only direct dependencies, and/or only those
        known to be outdated.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + API_PROJECT_COMPONENTS % (project_id)

        urlsep = "?"
        if isinstance(only_outdated, bool):
            url += "{}onlyOutdated={}".format(urlsep, str(only_outdated).lower())
            urlsep = "&"

        if isinstance(only_direct, bool):
            url += "{}onlyDirect={}".format(urlsep, str(only_direct).lower())
            #urlsep = "&"

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }

        r = Auditor.get_paginated(url, headers=headers, verify=verify)
        if r is not None and type(r) is requests.Response:
            if r.status_code != 200:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print(f"Cannot get list of components in project: {r.status_code} {r.reason}")
                # TODO? raise AuditorRESTAPIException("Cannot get list of components in project", r)
                return {}
            return json.loads(r.text)

        # None or a type parsed from JSON
        return r

    @staticmethod
    def get_project_properties_list(host, key, project_id, verify=True):
        """
        Look up a list of project properties by its UUID.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (project_id is not None and project_id != "")

        url = host + (API_PROJECT_PROPERTIES % project_id)
        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = requests.get(url, headers=headers, verify=verify)
        if r.status_code != 200:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get project properties: {r.status_code} {r.reason}")
            # TODO? raise AuditorRESTAPIException("Cannot get project properties", r)
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
        """
        Return a list of dictionaries with basic information about
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
            url += "{}excludeInactive={}".format(urlsep, str(exclude_inactive).lower())
            urlsep = "&"

        # FIXME: As of DT 4.9.0 it seems the `onlyRoot=bool` handling is
        #  inverted vs. its documentation ("true" returns root and child
        #  projects, "false" returns only the root). If this gets fixed
        #  by upstream later (or behaved differently in other versions)
        #  we may want to query get_dependencytrack_version(), and maybe
        #  cache it for each "host", so we would only invert the boolean
        #  for some range of server versions...
        if isinstance(exclude_children, bool):
            url += "{}onlyRoot={}".format(urlsep, str(not exclude_children).lower())
            #urlsep = "&"

        headers = {
            "content-type": "application/json",
            "X-API-Key": key
        }
        r = Auditor.get_paginated(url, headers=headers, verify=verify)
        if r is not None and type(r) is requests.Response:
            if r.status_code != 200:
                raise AuditorRESTAPIException("Cannot get project list", r)
            return json.loads(r.text)

        # None or a type parsed from JSON
        return r

    @staticmethod
    def get_project_without_version_id(host, key, project_name, version, verify=True):
        """
        Look up a particular project instance by name and version,
        querying for a list of all projects and filtering that.

        NOTE: Please see whether the get_project_with_version_id() method
        works for you instead (should be less expensive computationally).

        Returns:

        * a string with project UUID reported by the REST API server
          if the HTTP request was successful and contained an UUID
          for this project name and version,
        * None if the HTTP request was successful but did not contain
          the UUID for this project name and version, or
        * an "" empty string upon REST API request HTTP error states;
        * methods used may raise exceptions on other types of errors.
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
        """
        Look up a particular project instance by name and version,
        using a dedicated REST API call for that purpose.

        Returns:

        * a string with project UUID reported by the REST API server
          if the HTTP request was successful and contained an UUID
          for this project name and version,
        * None if the HTTP request was successful but did not contain
          the UUID for this project name and version, or
        * an "" empty string upon REST API request HTTP error states;
        * methods used may raise exceptions on other types of errors.
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
        # May be None if key was not found for some reason (unsupported DT version?)
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
        wait=True, verify=True
    ):
        """
        Read original XML or JSON Bom file, re-encode it to DT server's liking,
        and upload into specified project instance (name+version), creating one
        if needed and requested (otherwise, you need to have created it earlier,
        perhaps by cloning an older version - for that, see clone_update_project()).

        Returns the event token (callers can poll for it, if they chose to not
        "wait" for completion via method arguments).
        """

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

        old_project_version_uuid = project_uuid
        old_project_version_info = None
        old_lastBOMImport = None
        try:
            if ((old_project_version_uuid is None or len(old_project_version_uuid) < 1)
                    and project_name is not None and version is not None):
                old_project_version_uuid = Auditor.get_project_with_version_id(host, key, project_name, version, verify)
            if len(old_project_version_uuid) < 1:
                # HTTP error reported when retrieving, but
                # connection etc. did not fail so not None.
                # This re-assignment simplifies checks below.
                old_project_version_uuid = None
            if old_project_version_uuid is not None:
                old_project_version_info = Auditor.poll_project_uuid(host, key, old_project_version_uuid, True, verify)
            if old_project_version_info is not None:
                old_lastBOMImport = int(old_project_version_info["lastBomImport"])
        except Exception as ex:
            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Cannot get project '{str(old_project_version_uuid)}' (for '{project_name}' '{version}') info details before SBOM upload: {str(ex)}")
            pass

        r = requests.put(host + API_BOM_UPLOAD, data=json.dumps(payload), headers=headers, verify=verify)
        if r.status_code != 200:
            raise AuditorRESTAPIException(f"Cannot upload {filename}", r)

        bom_token = json.loads(r.text).get('token')
        if bom_token and wait:
            Auditor.poll_bom_token_being_processed(host, key, bom_token, wait=wait, verify=verify)

        if wait:
            new_project_version_uuid = old_project_version_uuid
            new_project_version_info = None
            new_lastBOMImport = None
            try:
                if new_project_version_uuid is None and project_name is not None and version is not None:
                    # FIXME: ` and auto_create is True` ?
                    new_project_version_uuid = Auditor.get_project_with_version_id(host, key, project_name, version, verify)
                if len(new_project_version_uuid) < 1:
                    # See comments in the block above.
                    new_project_version_uuid = None
                if new_project_version_uuid is not None:
                    new_project_version_info = Auditor.poll_project_uuid(host, key, new_project_version_uuid, True, verify)
                if new_project_version_info is not None:
                    # Expecting integer value of Unix epoch in milliseconds, e.g.
                    #  ...,"lastBomImport":1724506650367,...
                    new_lastBOMImport = int(new_project_version_info["lastBomImport"])
            except Exception as ex:
                if Auditor.DEBUG_VERBOSITY > 0:
                    print(f"Cannot get project '{new_project_version_uuid}' (for '{project_name}' '{version}') info details after SBOM upload: {str(ex)}")
                pass

            if new_lastBOMImport is None or new_lastBOMImport < 1:
                raise AuditorException(f"Cannot upload {filename}: project '{new_project_version_uuid}' (for '{project_name}' '{version}') info details report a bogus lastBomImport value: {str(new_lastBOMImport)}")

            if old_lastBOMImport is not None and new_lastBOMImport == old_lastBOMImport:
                raise AuditorException(f"Cannot upload {filename}: project '{new_project_version_uuid}' (for '{project_name}' '{version}') info details report same lastBomImport value as before import: {str(new_lastBOMImport)}")

            if Auditor.DEBUG_VERBOSITY > 0:
                print(f"Uploaded BOM '{filename}' into project '{new_project_version_uuid}' (for '{project_name}' '{version}'), it reports lastBomImport: {str(new_lastBOMImport)} (old one was {str(old_lastBOMImport)}) and token '{bom_token}'")

        return bom_token

    @staticmethod
    def clone_project_by_uuid(
            host, key, old_project_version_uuid,
            new_version, new_name=None, includeALL=True,
            includeACL=None, includeAuditHistory=None,
            includeComponents=None, includeProperties=None,
            includeServices=None, includeTags=None,
            includePolicyViolations=None,
            makeCloneLatest=None,
            wait=True, verify=True, safeSleep=3
    ):
        """
        Clone an existing specified project instance (name+version) chosen by
        its UUID, optionally inheriting existing components, analysis verdicts,
        etc.

        Can rename the project into a "new_name" if required (e.g. for
        feature branches), and assign the "new_version" to the clone.

        See also set_project_active() to perhaps deactivate the obsolete
        revision on the DT server.

        Some REST API operations are available since Dependency Track server
        4.11 and 4.12, so this method would ask for server version if not
        known yet (is cached by that method).

        Returns UUID of the new project instance upon success.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (old_project_version_uuid is not None and old_project_version_uuid != "")
        assert (new_version is not None and new_version != "")

        if Auditor.DEBUG_VERBOSITY > 2:
            print(f"Cloning project+version entity {old_project_version_uuid} to new version {new_version}...")

        old_project_version_info = Auditor.poll_project_uuid(host, key, old_project_version_uuid, True, verify)

        # Note that DT does not constrain the ability to assign arbitrary
        # values (which match the schema) to project name and version -
        # even if they seem to duplicate an existing entity. Project UUID
        # of each instance is what matters. Same-ness of names allows it
        # to group separate versions of the project.
        # UPDATE: Fixed in DT-4.9.0, see https://github.com/DependencyTrack/dependency-track/issues/2958
        # Server side definitive implementation (e.g. param names) is at
        #   https://github.com/DependencyTrack/dependency-track/blob/master/src/main/java/org/dependencytrack/resources/v1/vo/CloneProjectRequest.java
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

        # Some options are only available since recent DT releases
        # so to avoid surprises for those who still run slightly
        # older servers, we only invoke these options when supported:
        dt_ver_major = None
        dt_ver_minor = None
        dt_ver_patch = None
        if host not in Auditor.cached_dependencytrack_versions:
            Auditor.get_dependencytrack_version(host, key, verify)

        if host in Auditor.cached_dependencytrack_versions:
            try:
                dt_version = Auditor.cached_dependencytrack_versions[host].get('version', None)
                if Auditor.DEBUG_VERBOSITY > 3:
                    print (f"Checking server version for certain options: parsing '{dt_version}'.")
                if dt_version is not None:
                    dt_version = dt_version.split(".")
                    if len(dt_version) > 1:
                        # Got at least major/minor; are they ints?
                        dt_ver_major = int(dt_version[0])
                        dt_ver_minor = int(dt_version[1])
                        # May raise exception if not present?
                        dt_ver_patch = int(dt_version[2])
            except Exception as ignored:
                pass

        if dt_ver_major is not None and dt_ver_minor is not None:
            if Auditor.DEBUG_VERBOSITY > 3:
                print (f"Checking server version for certain options: got '{dt_ver_major}'.'{dt_ver_minor}'.'{dt_ver_patch}'.")

            if dt_ver_major > 4 or \
                    ( dt_ver_major == 4 and dt_ver_minor >= 11):
                # since DT 4.11 https://github.com/DependencyTrack/dependency-track/issues/2875
                payload["includePolicyViolations"] = (includePolicyViolations if (includePolicyViolations is not None) else (includeALL is True))

            if dt_ver_major > 4 or \
                    ( dt_ver_major == 4 and dt_ver_minor >= 12):
                if makeCloneLatest is not None:
                    # since DT 4.12 https://github.com/DependencyTrack/dependency-track/pull/4184
                    payload["makeCloneLatest"] = makeCloneLatest
        else:
            if Auditor.DEBUG_VERBOSITY > 3:
                print (f"Server version was not detected, not trying options for DependencyTrack server 4.11 or newer")

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
            # Before DT 4.11, project-cloning is not atomic and
            # the new instance's component count grows over time
            # until it hits the original numbers. Only after that
            # should SBOM upload happen, for example.
            new_project_version_info = Auditor.poll_project_uuid(host, key, new_project_uuid, wait=wait, verify=verify)
            try:
                old_count = old_project_version_info["metrics"]["components"]
                if old_count > 0:
                    try:
                        new_count = new_project_version_info["metrics"]["components"]
                    except Exception as exDict:
                        new_count = -1

                    while new_count < old_count:
                        time.sleep(5)
                        Auditor.request_project_metrics_refresh(host, key, new_project_uuid, wait=wait, verify=verify)
                        new_project_version_info = Auditor.poll_project_uuid(host, key, new_project_uuid, wait=wait, verify=verify)
                        try:
                            new_count = new_project_version_info["metrics"]["components"]
                        except Exception as exDict:
                            new_count = -1
            except Exception as ex:
                # Could not pass the dict?
                if Auditor.DEBUG_VERBOSITY > 2:
                    print(f"Could not poll and wait for new project to have same component count as the old instance: %s" % (str(ex)))
            if Auditor.DEBUG_VERBOSITY > 2:
                print(f"The cloned project+version entity {new_project_uuid} has at least as many components ({new_count}) as the original entity {old_project_version_uuid} ({old_count})")

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
            includePolicyViolations=None,
            makeCloneLatest=None,
            wait=True, verify=True, safeSleep=3
    ):
        """
        This method determines the UUID of an existing project instance
        by its name and version, and calls clone_project_by_uuid().
        See that method for detailed description.
        """

        assert (host is not None and host != "")
        assert (key is not None and key != "")
        assert (old_project_name is not None and old_project_name != "")
        assert (old_project_version is not None and old_project_version != "")
        assert (new_version is not None and new_version != "")

        old_project_version_uuid =\
            Auditor.get_project_with_version_id(host, key, old_project_name, old_project_version, verify)
        assert (old_project_version_uuid is not None and len(old_project_version_uuid) > 0)
        return Auditor.clone_project_by_uuid(
            host, key, old_project_version_uuid,
            new_version, new_name, includeALL,
            includeACL, includeAuditHistory,
            includeComponents, includeProperties,
            includeServices, includeTags,
            includePolicyViolations,
            makeCloneLatest,
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
            includePolicyViolations=None,
            makeCloneLatest=None,
            uploadIntoClone=True,
            wait=True, verify=True, safeSleep=3
    ):
        """
        Clones an existing project and uploads a new SBOM document into
        one of them (depending on value of "uploadIntoClone", by default
        updating the clone -- but it makes sense for some workflows to
        keep the same project UUID as the current tip of code evolution,
        and clone off snapshots of older revisions to keep them "as is"),
        in one swift operation.

        If "uploadIntoClone==False", the "new_name" and "new_version"
        would be applied to the original project (into which the new
        BOM document revision would be imported). Take care about
        assigning correct values to "activate_old"/"activate_new"
        (they still refer to the pre-existing and newly-cloned project
        instances).

        Note: the "include*" and "makeCloneLatest" arguments are passed
        into the REST API call to be processed by the Dependency-Track
        server. Setting "makeCloneLatest=True" may be logically at odds
        with setting "uploadIntoClone=False".

        Returns UUID of the new cloned project, or raises exceptions upon
        errors along the way.

        TODO: Parse Bom.Metadata.Component if present (XML, JSON) to get
        fallback name and/or version.
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

        assert (old_project_version_uuid is not None and len(old_project_version_uuid) > 0)
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
        # Even if we clone a project in a way that the new clone would be
        # just a snapshot of the old state (uploadIntoClone==False), we try
        # to do it transactionally -- only mangle the original instance's
        # version (and name) into new values after the clone has appeared.
        mustPatchCloneVersion = False
        try:
            # Even if uploadIntoClone==False, we first clone using the
            # new name and version (to stake our claim in those values):
            new_project_uuid = Auditor.clone_project_by_uuid(
                host, key, old_project_version_uuid,
                new_version, new_name, includeALL,
                includeACL, includeAuditHistory,
                includeComponents, includeProperties,
                includeServices, includeTags,
                includePolicyViolations,
                makeCloneLatest,
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
                old_project_version_uuid,   # fake temp version
                new_name, includeALL,
                includeACL, includeAuditHistory,
                includeComponents, includeProperties,
                includeServices, includeTags,
                includePolicyViolations,
                makeCloneLatest,
                wait=(wait if wait is not None and wait is not False else 240),
                verify=verify, safeSleep=safeSleep)
            mustPatchCloneVersion = True

        AuditorException.INSTANT_EXIT = fatalException

        assert (new_project_uuid is not None and new_project_uuid != "")

        if mustPatchCloneVersion or not uploadIntoClone:
            headers = {
                "content-type": "application/json",
                "X-API-Key": key
            }

            if uploadIntoClone:
                # Assume just the mustPatchCloneVersion fix-up from above
                # No changes to original project UUID instance here
                r = requests.patch(
                    host + API_PROJECT + '/{}'.format(new_project_uuid),
                    data=json.dumps({"version": "%s" % new_version}),
                    headers=headers, verify=verify)
                if r.status_code != 200:
                    raise AuditorRESTAPIException(f"Cannot patch {new_project_uuid} version", r)
            else:
                # Caller wants to change the original project instance
                # (by UUID), while our shiny new clone assumes the old
                # name+version which the original instance currently has:
                # 1. Rename clone to "oldvalue+tmp"
                # 2. Rename origin to final "newvalue"
                # 3. Rename clone to final "oldvalue"

                # NOTE: old name+version are ignored if an UUID
                # is provided (or learned). For renaming here we
                # use whatever we have on DT server in fact.
                # New ones are what the caller requested (or we
                # inherited from "old" project instance above).
                old_project_name = old_project_obj.get("name")
                old_project_version = old_project_obj.get("version")

                if Auditor.DEBUG_VERBOSITY > 0:
                    print(f"FLIP MANEUVER: Asked to assign " +
                          f"old project name '{old_project_name}' " +
                          f"+ version '{old_project_version}' to " +
                          f"new UUID '{new_project_uuid}' of the " +
                          f"clone (destined to be a mere snapshot), " +
                          f"and the new project name '{new_name}' " +
                          f"+ version '{new_version}' to original " +
                          f"UUID '{old_project_version_uuid}' (into " +
                          f"which we would upload new BOM iteration)")

                # 1. Rename new clone to "oldvalue+tmp"
                r = requests.patch(
                    host + API_PROJECT + '/{}'.format(new_project_uuid),
                    data=json.dumps({
                        "name": "%s" % old_project_name,
                        "version": "%s-tmp-%s" % (old_project_version, new_project_uuid),
                    }),
                    headers=headers, verify=verify)
                if r.status_code != 200:
                    raise AuditorRESTAPIException(f"Cannot patch new {new_project_uuid} name+version", r)

                # 2. Rename old origin to "newvalue"
                r = requests.patch(
                    host + API_PROJECT + '/{}'.format(old_project_version_uuid),
                    data=json.dumps({
                        "name": "%s" % new_name,
                        "version": "%s" % new_version,
                    }),
                    headers=headers, verify=verify)
                if r.status_code != 200:
                    raise AuditorRESTAPIException(f"Cannot patch old {old_project_version_uuid} name+version", r)

                # 3. Rename new clone to "oldvalue" finally
                r = requests.patch(
                    host + API_PROJECT + '/{}'.format(new_project_uuid),
                    data=json.dumps({"version": "%s" % old_project_version}),
                    headers=headers, verify=verify)
                if r.status_code != 200:
                    raise AuditorRESTAPIException(f"Cannot patch new {new_project_uuid} name+version", r)

            if mustPatchCloneVersion and Auditor.DEBUG_VERBOSITY > 2:
                print(f"Completed the workaround with intermediate version value")

        bom_token = Auditor.read_upload_bom(
            host, key, project_name=None, version=None,
            filename=filename, auto_create=False,
            project_uuid=(new_project_uuid if uploadIntoClone else old_project_version_uuid),
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
        """
        Get version information of the Dependency-Track server instance itself.

        Returns a dict with information reported by the REST API server
        if the HTTP request was successful, or an "" empty string upon
        REST API request HTTP error states (may raise exceptions on other
        types of errors).
        """

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

        Auditor.cached_dependencytrack_versions[host] = response_dict
        return response_dict

    @staticmethod
    def close_request_session(catchExceptions=True):
        """
        To err on the safe side (e.g. avoid "too many open files") the
        consumer code may want to close the HTTP client sessions.

        Note we may not want to do this after each and every request
        (e.g. inside the methods above), since they might benefit
        under the hood from connection pooling or when the server
        supports multiple queries per TCP session.

        For more details see e.g.
        https://stackoverflow.com/questions/10115126/python-requests-close-http-connection

        This method allows the consumer code to not bother about the
        classes needed for HTTP client implementation in DTrackAuditor.

        The catchExceptions parameter tells this method to try/except
        and so not propagate any errors to consumer (making this a
        safer but only best-effort activity).
        """
        if catchExceptions:
            try:
                requests.session().close()
            except Exception as ignored:
                pass
        else:
            requests.session().close()
