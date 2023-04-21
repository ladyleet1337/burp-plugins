from burp import IBurpExtender, IScannerCheck
from java.io import PrintWriter
import re

# Basic and complex DOM-based XSS payloads
payloads = [
    "<script>alert(1);</script>",
    "javascript:alert(1)",
    "alert(String.fromCharCode(88, 83, 83));"
    # Add more payloads as needed
]

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("DOM XSS Detector")
        callbacks.registerScannerCheck(self)

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        for payload in payloads:
            if payload.lower() in baseRequestResponse.getResponse().tostring().lower():
                issues.append(self.createIssue(baseRequestResponse, payload))

        return issues

    def createIssue(self, baseRequestResponse, payload):
        issue = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        return self._callbacks.applyMarkersToResponse(baseRequestResponse, None, [(payload, issue)])

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1 if existingIssue.getIssueName() == newIssue.getIssueName() else 0

