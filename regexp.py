from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Vulnerability Detection Plugin")

        callbacks.registerScannerCheck(self)

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

    def doPassiveScan(self, baseRequestResponse):
        issues = []

        # Define your regular expressions and vulnerability checks here
        vulnerability_checks = [
            {
                "name": "Cross-Site Scripting (XSS)",
                "regexes": [
                    re.compile(r'<[a-z]+[^>]*\s(on[a-z]+)\s*=\s*["\']?[^"\'<>]+', re.IGNORECASE)
                ]
            },
            {
                "name": "SQL Injection (SQLi)",
                "regexes": [
                    re.compile(r"((\%27)|(\'))\s*((\%6F)|o|(\%4F))\s*((\%72)|r|(\%52))", re.IGNORECASE)
                ]
            },
            {
                "name": "Server-Side Request Forgery (SSRF)",
                "regexes": [
                    re.compile(r"http(s)?://(127\.0\.0\.1|localhost|0\.0\.0\.0)", re.IGNORECASE)
                ]
            },
            {
                "name": "XML External Entity (XXE)",
                "regexes": [
                    re.compile(r"<!ENTITY\s+\S+\s+SYSTEM\s+\"file:", re.IGNORECASE)
                ]
            },
            {
                "name": "OS Command Injection",
                "regexes": [
                    re.compile(r"(?<!\w)(?:\||\;|\&|\^|\(|\)|\`)\s*(?:sleep|ping|nslookup|cmd|bash|python|perl|ruby|nc|wget|curl)(?!\w)", re.IGNORECASE)
                ]
            },
            {
                "name": "Local File Inclusion (LFI) and Remote File Inclusion (RFI)",
                "regexes": [
                    re.compile(r"(?i)(?:file|php):(?:(?:\.\./)+|(?:http|https|ftp):)", re.IGNORECASE)
                ]
            },
            {
                "name": "Server-Side Template Injection (SSTI)",
                "regexes": [
                    re.compile(r"\{\{[\s\S]*?\}\}", re.IGNORECASE),
                    re.compile(r"<%\s*?[^>]*?%>", re.IGNORECASE)
                ]
            },
            {
                "name": "Server-Side Includes (SSI)",
                "regexes": [
                    re.compile(r"<!--#\s*include\s+(?:virtual|file)=['\"]([^'\">]+)['\"]\s*-->", re.IGNORECASE)
                ]
            },
            {
                "name": "HTML Injection",
                "regexes": [
                    re.compile(r"<[a-zA-Z0-9]+[^>]*>", re.IGNORECASE)
                ]
            },
            {
                "name": "CRLF Injection",
                "regexes": [
                    re.compile(r"%0D%0A|%0A|%0D|\r|\n", re.IGNORECASE)

                                    ]
            },
            {
                "name": "Parameter Pollution",
                "regexes": [
                    re.compile(r"(\?|\&)([^=]+)\=([^&]+)\&\2\=", re.IGNORECASE)
                ]
            },
            {
                "name": "Web Cache Deception",
                "regexes": [
                    re.compile(r"(?i)(\.css|\.js)\?(?:.*)=", re.IGNORECASE)
                ]
            }
        ]

        # Perform the scan
        for check in vulnerability_checks:
            for regex in check["regexes"]:
                matches = regex.findall(self._helpers.bytesToString(baseRequestResponse.getResponse()))
                if matches:
                    issues.append(CustomScanIssue(baseRequestResponse.getHttpService(),
                                                  self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                                                  [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                                                  check["name"],
                                                  "The response contains potential " + check["name"] + " vulnerabilities.",
                                                  "High"))

        return issues

class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, request_response, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._request_response = request_response
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._request_response

    def getHttpService(self):
        return self._http_service

    def getRemediationDetail(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getRemediationBackground(self):
        return None
