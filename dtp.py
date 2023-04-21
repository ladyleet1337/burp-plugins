from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Directory Traversal Detector")

        callbacks.registerScannerCheck(self)

        return

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        response = baseRequestResponse.getResponse()
        response_info = self._helpers.analyzeResponse(response)
        
        body_offset = response_info.getBodyOffset()
        response_body = response[body_offset:].tostring()

        directory_traversal_pattern = r'\.\./|\.\.\\'
        match = re.search(directory_traversal_pattern, response_body)
        
        if match:
            issues.append(CustomScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [self._callbacks.applyMarkers(baseRequestResponse, None, [match.span()])],
                "Possible Directory Traversal",
                "A possible directory traversal pattern was found in the response.",
                "Information"))
        
        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

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

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
