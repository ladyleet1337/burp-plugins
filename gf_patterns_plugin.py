from burp import IBurpExtender, IHttpListener

# Define GF patterns to search for
GF_PATTERNS = [
    "GF-PATTERN-1",
    "GF-PATTERN-2",
    # Add more patterns here
]

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("GF Patterns Plugin")
        callbacks.registerHttpListener(self)

        print("GF Patterns Plugin loaded.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            response_info = self._helpers.analyzeResponse(response)

            # Get response body
            body_offset = response_info.getBodyOffset()
            response_body = response[body_offset:]

            # Check for GF patterns in the response body
            for pattern in GF_PATTERNS:
                if pattern in response_body:
                    print("GF Pattern found: %s" % pattern)
                    print("URL: %s" % messageInfo.getUrl())
