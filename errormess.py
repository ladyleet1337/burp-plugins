from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout
from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JTable, ListSelectionModel
from javax.swing.table import DefaultTableModel
import re

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    # ... (rest of the code)
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Error Message Checker")
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        self.patterns = []
        self.load_default_patterns()

    def load_default_patterns(self):
        default_patterns = [
            # ... (list of default patterns from previous response)
        ]

        for pattern in default_patterns:
            self.patterns.append(re.compile(pattern))

    def getTabCaption(self):
        return "Error Message Rules"

    def getUiComponent(self):
        self._panel = JPanel(BorderLayout())

        self._table_model = DefaultTableModel(
            [],
            columnIdentifiers=["Pattern"]
        )
        self._table = JTable(self._table_model)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._scroll_pane = JScrollPane(self._table)

        self._text_area = JTextArea()
        self._scroll_pane_text_area = JScrollPane(self._text_area)

        self._add_button = JButton("Add Pattern", actionPerformed=self.add_pattern)
        self._remove_button = JButton("Remove Pattern", actionPerformed=self.remove_pattern)

        self._buttons_panel = JPanel()
        self._buttons_panel.add(self._add_button)
        self._buttons_panel.add(self._remove_button)

        self._panel.add(self._scroll_pane, BorderLayout.CENTER)
        self._panel.add(self._scroll_pane_text_area, BorderLayout.NORTH)
        self._panel.add(self._buttons_panel, BorderLayout.SOUTH)

        return self._panel

    def add_pattern(self, event):
        pattern = self._text_area.text.strip()
        if pattern:
            self._table_model.addRow([pattern])
            self.patterns.append(re.compile(pattern))

    def remove_pattern(self, event):
        selected_row = self._table.getSelectedRow()
        if selected_row != -1:
            self._table_model.removeRow(selected_row)
            self.patterns.pop(selected_row)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        response = self._helpers.bytesToString(messageInfo.getResponse())
        for pattern in self.patterns:
            if pattern.search(response):
                self._callbacks.issueAlert("Error message found: " + pattern.pattern)
                break

