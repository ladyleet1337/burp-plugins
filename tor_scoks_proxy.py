from burp import IBurpExtender
from burp import IHttpListener

import socket
import socks

class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        # Set the extension name
        callbacks.setExtensionName("Tor SOCKS Proxy")

        # Register the IHttpListener
        callbacks.registerHttpListener(self)

        # Configure SOCKS proxy settings
        self._configure_socks_proxy()

    def _configure_socks_proxy(self):
        socks_proxy_host = "127.0.0.1"
        socks_proxy_port = 9050
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_proxy_host, 
socks_proxy_port)
        socket.socket = socks.socksocket

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We don't need to modify the request or response, so just return
        return

