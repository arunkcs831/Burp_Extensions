from burp import IBurpExtender, IHttpListener, IExtensionStateListener
from javax.swing import JPanel, JLabel, JTextField, JButton, BoxLayout
from java.awt import BorderLayout
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Session Replacer")
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        # Default session config
        self.session_name = ""
        self.session_value = ""

        # Setup UI
        self.init_ui()
        callbacks.addSuiteTab(self)

    def init_ui(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.name_label = JLabel("Session Name (e.g., JSESSIONID):")
        self.name_input = JTextField(30)

        self.value_label = JLabel("Session Value:")
        self.value_input = JTextField(30)

        self.submit_button = JButton("Submit", actionPerformed=self.update_session)

        self.panel.add(self.name_label)
        self.panel.add(self.name_input)
        self.panel.add(self.value_label)
        self.panel.add(self.value_input)
        self.panel.add(self.submit_button)

    def getTabCaption(self):
        return "Session Replacer"

    def getUiComponent(self):
        return self.panel

    def update_session(self, event):
        self.session_name = self.name_input.getText().strip()
        self.session_value = self.value_input.getText().strip()
        print("[Session Replacer] Session updated to: {}={}".format(self.session_name, self.session_value))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        # Only modify requests that are in scope
        if not self._callbacks.isInScope(messageInfo.getHttpService()):
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(request_info.getHeaders())

        # Replace cookie if present
        updated_headers = []
        for header in headers:
            if header.startswith("Cookie:"):
                cookies = header[len("Cookie:"):].strip().split("; ")
                new_cookies = []
                for c in cookies:
                    if c.startswith(self.session_name + "="):
                        new_cookies.append(f"{self.session_name}={self.session_value}")
                    else:
                        new_cookies.append(c)
                updated_headers.append("Cookie: " + "; ".join(new_cookies))
            else:
                updated_headers.append(header)

        body = messageInfo.getRequest()[request_info.getBodyOffset():]
        new_message = self._helpers.buildHttpMessage(updated_headers, body)
        messageInfo.setRequest(new_message)

    def extensionUnloaded(self):
        print("[Session Replacer] Extension unloaded.")
