from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

from java.io import PrintWriter
from java.net import URL
from java.util import ArrayList
from java.util import Arrays

import re

class BurpExtender(IBurpExtender, IScannerCheck):

    def	registerExtenderCallbacks(self, callbacks):
        # set up our extension
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.setExtensionName("SQL Injection Scanner")
        callbacks.registerScannerCheck(self)

    def doPassiveScan(self, baseRequestResponse):
        # look for instances of SQL injection error messages
        checkRequest = baseRequestResponse.getRequest()
        markers = ["You have an error in your SQL syntax",
                   "mysql_fetch_assoc",
                   "mysql_fetch_array",
                   "mysql_num_rows"]
        for marker in markers:
            if marker in self._helpers.bytesToString(checkRequest):
                return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(
                        baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(
                        baseRequestResponse, None, [self._helpers.stringToBytes(marker)])],
                    "SQL Injection", "High")]

        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # read payload from file
        with open("sarath", "r") as f:
            payloads = f.readlines()

        # make a request for each payload
        issues = []
        for payload in payloads:
            payload = payload.strip()
            # skip payloads that don't contain placeholders
            if "{" not in payload:
                continue
            # replace placeholders with payloads
            payloadsToInject = generatePayloadsFromTemplate(payload)
            # send request with payloads
            for payloadToInject in payloadsToInject:
                # insert the payload
                checkRequest = insertionPoint.buildRequest(payloadToInject)
                # make the request
                checkRequestResponse = self._callbacks.makeHttpRequest(
                    baseRequestResponse.getHttpService(), checkRequest)
                # look for instances of SQL injection error messages
                markers = ["You have an error in your SQL syntax",
                           "mysql_fetch_assoc",
                           "mysql_fetch_array",
                           "mysql_num_rows"]
                for marker in markers:
                    if marker in self._helpers.bytesToString(checkRequestResponse):
                        issues.append(CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            self._helpers.analyzeRequest(
                                baseRequestResponse).getUrl(),
                            [self._callbacks.applyMarkers(
                                checkRequestResponse, None, [self._helpers.stringToBytes(marker)])],
                            "SQL Injection", "High"))
                        break

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        # if two issues are the same, just return one of them
        if existingIssue.getUrl() == newIssue.getUrl() and \
           existingIssue.getIssueName() == newIssue.getIssueName() and \
           existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1
        else:
            return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._severity = severity

    def getUrl(self):
        return self
