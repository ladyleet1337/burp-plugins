from burp import IBurpExtender, IScannerCheck
from java.io import PrintWriter
import re
import urllib

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SSTI and XSS Detection")
        callbacks.registerScannerCheck(self)
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        issues = []
        payloads = self.generate_payloads()

        for payload in payloads:
            check_request = insertionPoint.buildRequest(payload)
            check_response = self._callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), check_request
            )

            if self.detect_vulnerability(check_response, payload):
                issues.append(self.create_issue(baseRequestResponse, payload))
                break

        return issues

    def doPassiveScan(self, baseRequestResponse):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

    def generate_payloads(self):
        basic_payloads = [
            # AngularJS SSTI payload
            "{{'7'*7}}",
            # Twig SSTI payload
            "{{7*7}}",
            # Basic XSS payload
            "<script>alert('XSS')</script>",
            # Polyglot XSS payload
            'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e'
        ]

        encoded_payloads = []

        for payload in basic_payloads:
            # URL encoding
            encoded_payloads.append(urllib.quote(payload))
            # Double URL encoding
            encoded_payloads.append(urllib.quote(urllib.quote(payload)))
            # HTML entity encoding
            encoded_payloads.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
            # JavaScript string splitting
            splitted = payload[:len(payload) // 2] + "'+'" + payload[len(payload) // 2:]
            encoded_payloads.append(splitted)

        return encoded_payloads

    def detect_vulnerability(self, response, payload):
        response_info = self._helpers.analyzeResponse(response)
        response_body = response[response_info.getBodyOffset():].tostring()
        return payload in response_body

    def create_issue(self, baseRequestResponse, payload):
        http_service = baseRequestResponse.getHttpService()
        url = self._helpers.analyzeRequest(http_service, baseRequestResponse.getRequest()).getUrl()
        issue_name = "Potential SSTI/XSS Vulnerability - Payload: {}".format(payload)

        return CustomScanIssue(
            http_service,
           
