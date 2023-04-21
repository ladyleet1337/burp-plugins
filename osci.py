from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.util import ArrayList
import base64
import re

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("OS Command Injection Detector")
        callbacks.registerScannerCheck(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        self.stdout.println("Plugin loaded successfully")

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        request = baseRequestResponse.getRequest()
        response = baseRequestResponse.getResponse()
        analyzed_request = self._helpers.analyzeRequest(request)
        parameters = analyzed_request.getParameters()

        # Define payloads for Linux and Windows command injection
        payloads = [
            {'os': 'Linux', 'payload': 'sleep 3', 'encoded_payload': 'c2xlZXAgMw=='},
            {'os': 'Windows', 'payload': 'ping -n 3 127.0.0.1', 'encoded_payload': 'cGluZyAtbiAzIDEyNy4wLjAuMQ=='}
        ]

        for parameter in parameters:
            for payload in payloads:
                test_request = self._helpers.updateParameter(request, self._helpers.buildParameter(parameter.getName(),
                                     base64.b64decode(payload['encoded_payload']), parameter.getType()))
                test_response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), test_request)

                if self.detect_time_delay(response, test_response):
                    issues.append(CustomScanIssue(baseRequestResponse.getHttpService(),
                                  self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                  [self._callbacks.applyMarkers(test_request, None, None)],
                                  "OS Command Injection - " + payload['os'],
                                  "The application seems to be vulnerable to OS command injection.",
                                  "High", "Certain"))

        return issues

    def detect_time_delay(self, original_response, test_response):
        original_time = self._helpers.analyzeResponse(original_response).getDate()
        test_time = self._helpers.analyzeResponse(test_response).getDate()
        time_difference = (test_time - original_time).total_seconds()

        return time_difference >= 3

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

