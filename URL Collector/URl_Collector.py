from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.util import ArrayList
from javax.swing import JPanel, JTable, JScrollPane, JButton, JMenuItem, BoxLayout
from javax.swing.table import DefaultTableModel
from java.awt import Dimension, Toolkit
from java.awt.datatransfer import StringSelection

# Custom non-editable table model
class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Collector")

        self.autoLoggingEnabled = True
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        self.createUI()

        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

    def createUI(self):
        columnNames = ["Domain", "Path", "Method", "No. of Params", "Logs Saved", "Tested", "Autorize", "Copy"]
        self.model = NonEditableTableModel(columnNames, 0)
        self.table = JTable(self.model)
        self.table.setRowSelectionAllowed(True)

        # Set column widths
        self.table.getColumnModel().getColumn(0).setPreferredWidth(200)
        self.table.getColumnModel().getColumn(1).setPreferredWidth(300)

        scrollPane = JScrollPane(self.table)
        scrollPane.setPreferredSize(Dimension(1000, 350))

        clearButton = JButton("Clear Table", actionPerformed=self.clearTable)
        self.toggleButton = JButton("Auto-Logging: ON", actionPerformed=self.toggleAutoLogging)

        self.panel.add(scrollPane)
        self.panel.add(self.toggleButton)
        self.panel.add(clearButton)

    def getTabCaption(self):
        return "URL Collector"

    def getUiComponent(self):
        return self.panel

    def toggleAutoLogging(self, event):
        self.autoLoggingEnabled = not self.autoLoggingEnabled
        status = "ON" if self.autoLoggingEnabled else "OFF"
        self.toggleButton.setText("Auto-Logging: " + status)

    def clearTable(self, e):
        self.model.setRowCount(0)

    def createMenuItems(self, invocation):
        menu = ArrayList()
        messages = invocation.getSelectedMessages()
        if messages:
            menuItem = JMenuItem("Send to URL Collector", actionPerformed=lambda x: self.addToTable(messages[0]))
            menu.add(menuItem)
        return menu

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not self.autoLoggingEnabled:
            return
        if toolFlag != self.callbacks.TOOL_PROXY:
            return

        url = self.helpers.analyzeRequest(messageInfo).getUrl()
        if not self.callbacks.isInScope(url):
            return

        reqInfo = self.helpers.analyzeRequest(messageInfo)
        method = reqInfo.getMethod()
        params = reqInfo.getParameters()

        if method == "POST" or (method == "GET" and url.getQuery() is not None):
            self.addToTable(messageInfo)

    def addToTable(self, messageInfo):
        reqInfo = self.helpers.analyzeRequest(messageInfo)
        urlObj = reqInfo.getUrl()
        method = reqInfo.getMethod()
        params = reqInfo.getParameters()

        domain = "{}://{}".format(urlObj.getProtocol(), urlObj.getHost())
        path = urlObj.getPath()
        query = urlObj.getQuery()
        fullPath = path + ("?" + query if query else "")
        paramCount = len(params)

        row = [domain, fullPath, method, str(paramCount), "Yes", "", "Yes", "Copy"]
        self.model.addRow(row)

        rowIndex = self.model.getRowCount() - 1
        self.addCopyFunction(rowIndex)

    def addCopyFunction(self, rowIndex):
        def mouseClickedHandler(event):
            if event.getClickCount() == 1:
                column = self.table.columnAtPoint(event.getPoint())
                row = self.table.rowAtPoint(event.getPoint())
                if column == 7 and row == rowIndex:
                    self.copyToClipboard(row)
        self.table.addMouseListener(mouseClickedHandler)

    def copyToClipboard(self, row):
        values = [self.model.getValueAt(row, col) for col in range(7)]  # skip Copy column
        text = "\t".join(values)
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
