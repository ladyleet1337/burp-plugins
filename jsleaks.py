from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import os
import re
import subprocess

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("JSLeak Burp Plugin")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            # Get the URL of the response message
            url = messageInfo.getUrl()

            # Check if the URL is within the target domain
            if url.getHost().endswith("example.com"):
                # Check if the response contains JS code
                response = messageInfo.getResponse()
                responseInfo = self.helpers.analyzeResponse(response)
                if "javascript" in responseInfo.getStatedMimeType():
                    # Run jsleak on the URL containing JS code
                    jsleak_bin_path = os.path.join(os.getenv("GOPATH"), "bin", "jsleak")
                    js_url = url.toString()
                    try:
                        subprocess.run([jsleak_bin_path, js_url])
                    except:
                        self.stderr.println("Error running jsleak for URL: " + js_url)
