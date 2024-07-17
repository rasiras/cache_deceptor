from burp import IBurpExtender, IHttpListener, IMessageEditorController, ITab
from java.io import PrintWriter
from javax.swing import JPanel, JTextArea, JScrollPane, JTabbedPane
from java.awt import BorderLayout
from org.python.core.util import StringUtil
import json

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("Cache Header Detector")

        # Create the UI
        self._tab = JPanel(BorderLayout())
        self._log_area = JTextArea()
        self._scroll_pane = JScrollPane(self._log_area)
        self._tab.add(self._scroll_pane, BorderLayout.CENTER)

        callbacks.addSuiteTab(self)

        # Register the HTTP listener
        callbacks.registerHttpListener(self)

        self._stdout.println("Cache Header Detector extension loaded")

    def getTabCaption(self):
        return "Cache Headers"

    def getUiComponent(self):
        return self._tab

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            if response:
                analyzedResponse = self._helpers.analyzeResponse(response)
                headers = analyzedResponse.getHeaders()

                # Hardcoded cache headers to look for
                cache_headers = [
                    "cf-cache-status: HIT",
                    "cf-cache-status: MISS",
                    "X-Cache: HIT",
                    "X-Cache: MISS",
                    "X-Cache: TCP_HIT",
                    "X-Cache: TCP_MISS",
                    "X-Cache: Hit from cloudfront",
                    "X-Cache: Miss from cloudfront"
                ]

                # Check if response body is JSON
                body_offset = analyzedResponse.getBodyOffset()
                body = response[body_offset:].tostring()

                if self.is_json(body):
                    for header in headers:
                        if any(cache_header in header for cache_header in cache_headers):
                            url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
                            self.log_cache_hit(url)
                            break  # Only log once per response

    def is_json(self, body):
        try:
            json.loads(self._helpers.bytesToString(body))
            return True
        except ValueError:
            return False

    def log_cache_hit(self, url):
        log_entry = "URL: {}\n".format(url)
        self._log_area.append(log_entry)
        self._log_area.append("=" * 50 + "\n")


