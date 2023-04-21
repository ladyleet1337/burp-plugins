from burp import IBurpExtender, IScannerCheck, IScanIssue
import re

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("SQL Injection Scanner")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        # List of common SQL error messages
        sql_errors = [
            "sql syntax.*mysql",
            "warning.*mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "microsoft ole db provider for odbc drivers",
            "syntax error in insert into statement",
            "unclosed quotation mark before the character string",
            "syntax error or access violation",
            "procedure or function .* expects parameter",
            "conversion failed when converting the .* value",
            "you have an error in your sql syntax"
        ]

        # Get response body
        response_body = self._helpers.bytesToString(baseRequestResponse.getResponse())

        # Check for SQL error messages in the response
        for error in sql_errors:
            if re.search(error, response_body, re.IGNORECASE):
                return [CustomScanIssue(baseRequestResponse.getHttpService(),
                                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                        [baseRequestResponse],
                                        "Potential SQL Injection Vulnerability",
                                        "The response contains SQL error messages")]

        return None

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_response_list, name, detail):
        self._http_service = http_service
        self._url = url
        self._request_response_list = request_response_list
        self._name = name
        self._detail = detail

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._request_response_list

    def getHttpService(self):
        return self._http_service

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None
