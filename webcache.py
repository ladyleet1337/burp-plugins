from burp import IBurpExtender, IScannerCheck, IHttpRequestResponse, IScanIssue
from java.util import ArrayList
from java.io import PrintWriter
from java.net import URL
from urlparse import urlparse


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Web Cache Deception Detector")

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        issues = ArrayList()
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        request_url = request_info.getUrl()
        parsed_url = urlparse(request_url.toString())

        if parsed_url.path.endswith(".css") or parsed_url.path.endswith(".js"):
            return issues

        manipulated_request = self._helpers.toggleRequestMethod(baseRequestResponse.getRequest())
        new_request_info = self._helpers.analyzeRequest(manipulated_request)
        new_request_url = new_request_info.getUrl()

        new_request_response = self._callbacks.makeHttpRequest(
            baseRequestResponse.getHttpService(),
            manipulated_request
        )

        original_response_info = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        new_response_info = self._helpers.analyzeResponse(new_request_response.getResponse())

        if original_response_info.getStatusCode() == new_response_info.getStatusCode() \
                and original_response_info.getBodyOffset() == new_response_info.getBodyOffset() \
                and self._helpers.bytesToString(baseRequestResponse.getResponse()[original_response_info.getBodyOffset():]) \
                == self._helpers.bytesToString(new_request_response.getResponse()[new_response_info.getBodyOffset():]):
            issues.add(self.generate_issue(baseRequestResponse, request_url))

        return issues

    def generate_issue(self, request_response, url):
        issue = CustomScanIssue(
            request_response.getHttpService(),
            url,
            [request_response],
            "Web Cache Deception Vulnerability",
            "The application appears to be vulnerable to Web Cache Deception attacks.",
            "Medium"
        )
        return issue


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_responses, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._request_responses = request_responses
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._request_responses

    def getHttpService(self):
        return self._http_service

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getCustomHttpRequestResponse(self):
        return self._request_responses
