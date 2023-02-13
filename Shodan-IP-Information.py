from burp import IBurpExtender
from burp import ITab
from burp import IMessageEditorController
from burp import IHttpRequestResponse
from burp import IRequestInfo

from java.awt import Component
from java.awt import BorderLayout
from java.io import PrintWriter
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JScrollPane
from javax.swing.table import AbstractTableModel

import urllib2
import json

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.api_key = None
        self.ip_address = None

        self._jpanel = JTabbedPane()

        self.main_tab = JPanel()
        self.main_tab.setLayout(BorderLayout())
        self._jpanel.addTab("Main", self.main_tab)

        self.api_key_tab = JPanel()
        self._jpanel.addTab("APIs Key", self.api_key_tab)

        # Add IP address text field to main tab
        self.ip_address_field = JTextField("Enter IP address")
        self.main_tab.add(self.ip_address_field, BorderLayout.NORTH)
        
        # Add search button to main tab
        self.search_button = JButton("Search", actionPerformed=self.search)
        self.main_tab.add(self.search_button, BorderLayout.SOUTH)
        
        # Add results table to main tab
        self.table = JTable()
        self.main_tab.add(JScrollPane(self.table), BorderLayout.CENTER)
        
        # Add API Key text field to API Key tab
        self.api_key_field = JTextField("Enter API Key")
        self.api_key_tab.add(self.api_key_field, BorderLayout.NORTH)
        
        callbacks.addSuiteTab(self)
    
    def search(self, event):
        self.api_key = self.api_key_field.getText()
        self.ip_address = self.ip_address_field.getText()
        shodan_api = "https://api.shodan.io/shodan/host/" + self.ip_address + "?key=" + self.api_key
        response = urllib2.urlopen(shodan_api)
        data = json.loads(response.read())
        ports = data.get("data")
        os = data.get("os")
        asn = data.get("asn")
        country_code = data.get("country_code")
        hostnames = data.get("hostnames")
        
        rows = []
        for port in ports:
            rows.append([port.get("port"), port.get("transport"), port.get("product"), port.get("version"), os, asn, country_code, hostnames])
        self.table.setModel(self.TableModel(rows, ["Port", "Transport", "Product", "Version", "OS", "ASN", "Country Code", "Hostnames"]))
    def getTabCaption(self):
        return "Shodan Search v0.2.1"

    def getUiComponent(self):
        return self._jpanel

    class TableModel(AbstractTableModel):
        def __init__(self, rows, columns):
            self.rows = rows
            self.columns = columns

        def getRowCount(self):
            return len(self.rows)

        def getColumnCount(self):
            return len(self.columns)

        def getColumnName(self, columnIndex):
            return self.columns[columnIndex]

        def getValueAt(self, rowIndex, columnIndex):
             return self.rows[rowIndex][columnIndex]
