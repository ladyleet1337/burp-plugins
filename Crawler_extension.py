from burp import IBurpExtender, IHttpListener
from bs4 import BeautifulSoup
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Crawler Extension")
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if not message_is_request:
            response = message_info.getResponse()
            response_info = self._helpers.analyzeResponse(response)
            body = response[response_info.getBodyOffset():].tostring()
            content_type = response_info.getStatedMimeType()

            if content_type == "HTML":
                soup = BeautifulSoup(body, "html.parser")
                links = soup.find_all("a", href=True)

                for link in links:
                    url = link["href"]
                    if not re.match(r"^https?://", url):
                        base_url = "{}://{}:{}".format(
                            message_info.getHttpService().getProtocol(),
                            message_info.getHttpService().getHost(),
                            message_info.getHttpService().getPort()
                        )
                        url = base_url + link["href"]

                    if not self._callbacks.isInScope(url):
                        self._callbacks.includeInScope(url)
                        print("Included URL in scope: {}".format(url))

