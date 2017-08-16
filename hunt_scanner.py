import json
import os
import re
import urllib2
import urlparse
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IMessageEditorController
from burp import IScanIssue
from burp import IScannerCheck
from burp import ITab
from burp import ITextEditor
from java.awt import Desktop
from java.awt import Dimension
from java.awt import EventQueue
from java.awt.event import ActionListener
from java.awt.event import MouseAdapter
from java.lang import Runnable
from java.lang import Object
from java.lang import Thread
from javax.swing import DefaultCellEditor
from javax.swing import JCheckBox
from javax.swing import JEditorPane
from javax.swing import JList
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTable
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from javax.swing import JTree
from javax.swing import SwingUtilities
from javax.swing.event import HyperlinkListener
from javax.swing.event import ListSelectionListener
from javax.swing.event import TableModelListener
from javax.swing.event import TreeSelectionListener
from javax.swing.table import DefaultTableModel
from javax.swing.tree import DefaultMutableTreeNode
from javax.swing.tree import TreeSelectionModel
from org.python.core.util import StringUtil

# Using the Runnable class for thread-safety with Swing
class Run(Runnable):
    def __init__(self, runner):
        self.runner = runner

    def run(self):
        self.runner()

# TODO: Move other classes to different files
class BurpExtender(IBurpExtender, IExtensionStateListener, IScannerCheck, ITab, ITextEditor):
    EXTENSION_NAME = "HUNT - Scanner"

    # TODO: Figure out why this gets called twice
    def __init__(self):
        self.issues = Issues()
        self.view = View(self.issues)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.view.set_callbacks(callbacks)
        self.helpers = callbacks.getHelpers()
        self.view.set_helpers(self.helpers)
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.addSuiteTab(self)
        self.callbacks.registerScannerCheck(self)

    def doPassiveScan(self, request_response):
        raw_request = request_response.getRequest()
        raw_response = request_response.getResponse()
        request = self.helpers.analyzeRequest(raw_request)
        response = self.helpers.analyzeResponse(raw_response)

        parameters = request.getParameters()
        vuln_parameters = self.issues.check_parameters(self.helpers, parameters)

        is_not_empty = len(vuln_parameters) > 0

        if is_not_empty:
            self.issues.create_scanner_issues(self.view, self.callbacks, self.helpers, vuln_parameters, request_response)

        # Do not show any Bugcrowd found issues in the Scanner window
        return []

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.view.get_pane()

    def extensionUnloaded(self):
        print "HUNT - Scanner plugin unloaded"
        return

class View:
    def __init__(self, issues):
        self.json = issues.get_json()
        self.issues_object = issues
        self.issues = issues.get_issues()
        self.scanner_issues = issues.get_scanner_issues()
        self.scanner_panes = {}
        self.scanner_table_models = {}
        self.scanner_tables = {}
        self.is_scanner_panes = []

        self.set_vuln_tree()
        self.set_tree()
        self.set_scanner_table_models()
        self.set_scanner_panes()
        self.set_pane()
        self.set_tsl()

    def get_issues_object(self):
        return self.issues_object

    def set_callbacks(self, callbacks):
        self.callbacks = callbacks

    def set_helpers(self, helpers):
        self.helpers = helpers

    def get_helpers(self):
        return self.helpers

    def get_issues(self):
        return self.issues

    def get_scanner_issues(self):
        return self.scanner_issues

    def set_is_scanner_pane(self, scanner_pane):
        self.is_scanner_panes.append(scanner_pane)

    def get_is_scanner_pane(self, scanner_pane):
        for pane in self.get_is_scanner_panes():
            if pane == scanner_pane:
                return True

        return False

    def get_is_scanner_panes(self):
        return self.is_scanner_panes

    def set_vuln_tree(self):
        self.vuln_tree = DefaultMutableTreeNode("Vulnerability Classes")

        vulns = self.json["issues"]

        # TODO: Sort the functionality by name and by vuln class
        for vuln_name in vulns:
            vuln = DefaultMutableTreeNode(vuln_name)
            self.vuln_tree.add(vuln)

            parameters = self.json["issues"][vuln_name]["params"]

            for parameter in parameters:
                param_node = DefaultMutableTreeNode(parameter)
                vuln.add(param_node)

    # Creates a JTree object from the checklist
    def set_tree(self):
        self.tree = JTree(self.vuln_tree)
        self.tree.getSelectionModel().setSelectionMode(
            TreeSelectionModel.SINGLE_TREE_SELECTION
        )

    def get_tree(self):
        return self.tree

    def set_scanner_table_models(self):
        issues = self.issues

        for issue in issues:
            issue_name = issue["name"]
            issue_param = issue["param"]

            self.create_scanner_table_model(issue_name, issue_param)

    # Creates the tabs dynamically using data from the JSON file
    def set_scanner_panes(self):
        for issue in self.issues:
            issue_name = issue["name"]
            issue_param = issue["param"]
            key = issue_name + "." + issue_param

            top_pane = self.create_request_list_pane(issue_name)
            bottom_pane = self.create_tabbed_pane()

            scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, top_pane, bottom_pane)
            self.scanner_panes[key] = scanner_pane

    def get_scanner_panes(self):
        return self.scanner_panes

    def create_request_list_pane(self, issue_name):
        request_list_pane = JScrollPane()

        return request_list_pane

    # Creates a JTabbedPane for each vulnerability per functionality
    def create_tabbed_pane(self):
        tabbed_pane = JTabbedPane()
        tabbed_pane.add("Advisory", JScrollPane())
        tabbed_pane.add("Request", JScrollPane())
        tabbed_pane.add("Response", JScrollPane())

        self.tabbed_pane = tabbed_pane

        return tabbed_pane

    def set_tsl(self):
        tsl = TSL(self)
        self.tree.addTreeSelectionListener(tsl)

        return

    def set_pane(self):
        status = JTextArea()
        status.setLineWrap(True)
        status.setText("Nothing selected")
        self.status = status

        request_list_pane = JScrollPane()

        scanner_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                                  request_list_pane,
                                  self.tabbed_pane)

        self.pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                               JScrollPane(self.tree),
                               scanner_pane)

        self.pane.setDividerLocation(310)
        self.pane.getLeftComponent().setMinimumSize(Dimension(310, 300))

    def get_pane(self):
        return self.pane

    # TODO: Move all scanner table functions into its own ScannerTable class
    #       as well as ScannerTableModel for all scanner table model functions
    # TODO: Add column for parameter name
    # TODO: Fix path column to only show path. Use urllib2 to split URL.
    def create_scanner_table_model(self, issue_name, issue_param):
        key = issue_name + "." + issue_param
        is_model_exists = key in self.scanner_table_models

        if is_model_exists:
            return

        scanner_table_model = ScannerTableModel()
        scanner_table_model.addColumn("Checked")
        scanner_table_model.addColumn("Parameter")
        scanner_table_model.addColumn("Host")
        scanner_table_model.addColumn("Path")

        self.scanner_table_models[key] = scanner_table_model

    def set_scanner_table_model(self, scanner_issue, issue_name, issue_param, vuln_param):
        key = issue_name + "." + vuln_param
        scanner_table_model = self.scanner_table_models[key]

        # Using the addRow() method requires that the data type being passed to be of type
        # Vector() or Object(). Passing a Python object of type list in addRow causes a type
        # conversion error of sorts which presents as an ArrayOutOfBoundsException. Therefore,
        # row is an instantiation of Object() to avoid this error.
        row = Object()
        row = [False, issue_param, scanner_issue.getHttpService().getHost(), scanner_issue.getPath()]
        scanner_table_model.addRow(row)

        # Wait for ScannerTableModel to update as to not get an ArrayOutOfBoundsException.
        Thread.sleep(500)

        scanner_table_model.fireTableDataChanged()
        scanner_table_model.fireTableStructureChanged()

    def get_scanner_table_model(self, issue_name, issue_param):
        key = issue_name + "." + issue_param
        return self.scanner_table_models[key]

    def set_scanner_pane(self, scanner_pane, issue_name, issue_param):
        key = issue_name + "." + issue_param
        request_table_pane = scanner_pane.getTopComponent()

        if key in self.scanner_tables:
            scanner_table = self.scanner_tables[key]
        else:
            scanner_table = self.create_scanner_table(scanner_pane, issue_name, issue_param)
            self.scanner_tables[key] = scanner_table

        request_table_pane.getViewport().setView(scanner_table)
        request_table_pane.revalidate()
        request_table_pane.repaint()

    def create_scanner_table(self, scanner_pane, issue_name, issue_param):
        scanner_table_model = self.get_scanner_table_model(issue_name, issue_param)

        scanner_table = JTable(scanner_table_model)
        scanner_table.getColumnModel().getColumn(0).setCellEditor(DefaultCellEditor(JCheckBox()))
        scanner_table.putClientProperty("terminateEditOnFocusLost", True)
        scanner_table_listener = ScannerTableListener(self, scanner_table, issue_name, issue_param)
        scanner_table_model.addTableModelListener(scanner_table_listener)
        scanner_table_list_listener = IssueListener(self, scanner_table, scanner_pane, issue_name, issue_param)
        scanner_table.getSelectionModel().addListSelectionListener(scanner_table_list_listener)

        return scanner_table

    def set_tabbed_pane(self, scanner_pane, request_list, issue_hostname, issue_path, issue_name, issue_param):
        tabbed_pane = scanner_pane.getBottomComponent()
        scanner_issues = self.get_scanner_issues()

        for scanner_issue in scanner_issues:
            is_same_hostname = scanner_issue.getHostname() == issue_hostname
            is_same_path = scanner_issue.getPath() == issue_path
            is_same_name = scanner_issue.getIssueName() == issue_name
            is_same_param = scanner_issue.getParameter() == issue_param
            is_same_issue = is_same_hostname and is_same_path and is_same_name and is_same_param

            if is_same_issue:
                current_issue = scanner_issue
                self.set_context_menu(request_list, scanner_issue)
                break

        advisory_tab_pane = self.set_advisory_tab_pane(current_issue)
        tabbed_pane.setComponentAt(0, advisory_tab_pane)

        request_tab_pane = self.set_request_tab_pane(current_issue)
        tabbed_pane.setComponentAt(1, request_tab_pane)

        response_tab_pane = self.set_response_tab_pane(current_issue)
        tabbed_pane.setComponentAt(2, response_tab_pane)

    def set_advisory_tab_pane(self, scanner_issue):
        advisory_pane = JEditorPane()
        advisory_pane.setEditable(False)
        advisory_pane.setEnabled(True)
        advisory_pane.setContentType("text/html")
        link_listener = LinkListener()
        advisory_pane.addHyperlinkListener(link_listener)
        advisory = "<html><b>Location</b>: {}<br><br>{}</html>"
        advisory_pane.setText(advisory.format(scanner_issue.getUrl().encode("utf-8"),
                                         scanner_issue.getIssueDetail()))

        # Set a context menu
        self.set_context_menu(advisory_pane, scanner_issue)

        return JScrollPane(advisory_pane)

    def set_request_tab_pane(self, scanner_issue):
        '''
        raw_request = scanner_issue.getRequestResponse().getRequest()
        request_body = StringUtil.fromBytes(raw_request)
        request_body = request_body.encode("utf-8")

        request_tab_textarea = self.callbacks.createTextEditor()
        component = request_tab_textarea.getComponent()
        request_tab_textarea.setText(request_body)
        request_tab_textarea.setEditable(False)
        request_tab_textarea.setSearchExpression(scanner_issue.getParameter())

        # Set a context menu
        self.set_context_menu(component, scanner_issue)
        '''

        request_response = scanner_issue.getRequestResponse()
        controller = MessageController(request_response)
        message_editor = self.callbacks.createMessageEditor(controller, True)
        message_editor.setMessage(request_response.getRequest(), True)
        component = message_editor.getComponent()

        return component

    def set_response_tab_pane(self, scanner_issue):
        raw_response = scanner_issue.getRequestResponse().getResponse()
        response_body = StringUtil.fromBytes(raw_response)
        response_body = response_body.encode("utf-8")

        response_tab_textarea = self.callbacks.createTextEditor()
        component = response_tab_textarea.getComponent()
        response_tab_textarea.setText(response_body)
        response_tab_textarea.setEditable(False)

        # Set a context menu
        self.set_context_menu(component, scanner_issue)

        return component

    # TODO: Remove this function and use the built-in Burp Suite context menu
    # Pass scanner_issue as argument
    def set_context_menu(self, component, scanner_issue):
        self.context_menu = JPopupMenu()

        repeater = JMenuItem("Send to Repeater")
        repeater.addActionListener(PopupListener(scanner_issue, self.callbacks))

        intruder = JMenuItem("Send to Intruder")
        intruder.addActionListener(PopupListener(scanner_issue, self.callbacks))

        hunt = JMenuItem("Send to HUNT")

        self.context_menu.add(repeater)
        self.context_menu.add(intruder)

        context_menu_listener = ContextMenuListener(component, self.context_menu)
        component.addMouseListener(context_menu_listener)

    def get_context_menu(self):
        return self.context_menu

    def traverse_tree(self, tree, model, issue_name, issue_param, issue_count, total_count):
        root = model.getRoot()
        count = int(root.getChildCount())
        traverse = {}

        for i in range(count):
            node = model.getChild(root, i)
            traverse["node"] = node
            tree_issue_name = node.toString()

            is_issue_name = re.search(issue_name, tree_issue_name)

            if is_issue_name:
                child_count = node.getChildCount()

                for j in range(child_count):
                    child = node.getChildAt(j)
                    traverse["child"] = child
                    tree_param_name = child.toString()

                    is_param_name = re.search(issue_param, tree_param_name)

                    if is_param_name:
                        traverse["param_text"] = issue_param + " (" + str(issue_count) + ")"
                        break

                traverse["issue_text"] = issue_name + " (" + str(total_count) + ")"
                break

        return traverse

    def set_scanner_count(self, issue_name, issue_param, issue_count, total_count):
        tree = self.get_tree()
        model = tree.getModel()
        traverse = self.traverse_tree(tree, model, issue_name, issue_param, issue_count, total_count)
        node = traverse["node"]
        child = traverse["child"]

        print traverse["param_text"]
        print traverse["issue_text"]

        child.setUserObject(traverse["param_text"])
        model.nodeChanged(child)
        model.reload(node)

        node.setUserObject(traverse["issue_text"])
        model.nodeChanged(node)
        model.reload(node)

class MessageController(IMessageEditorController):
    def __init__(self, request_response):
        self._http_service = request_response.getHttpService()
        self._request = request_response.getRequest()
        self._response = request_response.getResponse()

    def getHttpService(self):
        return self._http_service

    def getRequest(self):
        return self._request

    def getResponse(self):
        return self._response

class LinkListener(HyperlinkListener):
    def hyperlinkUpdate(self, hle):
        if hle.EventType.ACTIVATED == hle.getEventType():
            desktop = Desktop.getDesktop()
            desktop.browse(hle.getURL().toURI())

class ScannerTableModel(DefaultTableModel):
    def getColumnClass(self, col):
        return True.__class__ if col == 0 else "".__class__

    def isCellEditable(self, row, col):
        return col == 0

class ScannerTableListener(TableModelListener):
    def __init__(self, view, scanner_table, issue_name, issue_param):
        self.view = view
        self.scanner_table = scanner_table
        self.issue_name = issue_name
        self.issue_param = issue_param

    def tableChanged(self, e):
        row = e.getFirstRow()
        col = e.getColumn()
        is_checked = self.scanner_table.getValueAt(row, col)
        is_changed = e.getType() == e.UPDATE

        if is_changed:
            self.view.get_issues_object().change_total_count(self.issue_name, is_checked)
            self.view.get_issues_object().change_issues_count(self.issue_name, self.issue_param, is_checked)
            issue_count = self.view.get_issues_object().get_issues_count(self.issue_name, self.issue_param)
            total_count = self.view.get_issues_object().get_total_count(self.issue_name)

            print self.issue_name + " " + self.issue_param + " " + str(issue_count) + " " + str(total_count)

            if is_checked:
                self.view.set_scanner_count(self.issue_name, self.issue_param, issue_count, total_count)
            else:
                self.view.set_scanner_count(self.issue_name, self.issue_param, issue_count, total_count)


class ContextMenuListener(MouseAdapter):
    def __init__(self, component, context_menu):
        self.component = component
        self.context_menu = context_menu

    def mousePressed(self, e):
        is_right_click = SwingUtilities.isRightMouseButton(e)

        if is_right_click:
            self.check(e)

    def check(self, e):
        is_list = isinstance(self.component, JList)

        if is_list:
            is_selection = self.component.getSelectedValue() is not None
            is_trigger = e.isPopupTrigger()
            is_context_menu = is_selection and is_trigger
            index = self.component.locationToIndex(e.getPoint())
            self.component.setSelectedIndex(index)

        self.context_menu.show(self.component, e.getX(), e.getY())

class PopupListener(ActionListener):
    def __init__(self, scanner_issue, callbacks):
        self.host = scanner_issue.getHttpService().getHost()
        self.port = scanner_issue.getHttpService().getPort()
        self.protocol = scanner_issue.getHttpService().getProtocol()
        self.request = scanner_issue.getRequestResponse().getRequest()
        self.callbacks = callbacks

        if self.protocol == "https":
            self.use_https = True
        else:
            self.use_https = False

    def actionPerformed(self, e):
        action = str(e.getActionCommand())

        repeater_match = re.search("Repeater", action)
        intruder_match = re.search("Intruder", action)

        is_repeater_match = repeater_match is not None
        is_intruder_match = intruder_match is not None

        if is_repeater_match:
            self.callbacks.sendToRepeater(self.host, self.port, self.use_https, self.request, None)

        if is_intruder_match:
            self.callbacks.sendToIntruder(self.host, self.port, self.use_https, self.request)

class TSL(TreeSelectionListener):
    def __init__(self, view):
        self.view = view
        self.tree = view.get_tree()
        self.pane = view.get_pane()
        self.scanner_issues = view.get_scanner_issues()
        self.scanner_panes = view.get_scanner_panes()

    def valueChanged(self, tse):
        pane = self.pane
        node = self.tree.getLastSelectedPathComponent()

        if node is None:
            return

        issue_name = node.getParent().toString()
        issue_param = node.toString()

        issue_name_match = re.search("\(", issue_name)
        issue_param_match = re.search("\(", issue_param)

        is_name_match = issue_name_match is not None
        is_param_match = issue_param_match is not None

        if is_name_match:
            issue_name = issue_name.split(" (")[0]

        if is_param_match:
            issue_param = issue_param.split(" (")[0]

        is_leaf = node.isLeaf()

        if node:
            if is_leaf:
                key = issue_name + "." + issue_param
                scanner_pane = self.scanner_panes[key]

                self.view.set_scanner_pane(scanner_pane, issue_name, issue_param)
                pane.setRightComponent(scanner_pane)
            else:
                print "No description for " + issue_name + " " + issue_param
        else:
            print "Cannot set a pane for " + issue_name + " " + issue_param

class IssueListener(ListSelectionListener):
    def __init__(self, view, table, scanner_pane, issue_name, issue_param):
        self.view = view
        self.table = table
        self.scanner_pane = scanner_pane
        self.issue_name = issue_name
        self.issue_param = issue_param

    def valueChanged(self, e):
        row = self.table.getSelectedRow()
        issue_param = self.table.getModel().getValueAt(row, 1)
        hostname = self.table.getModel().getValueAt(row, 2)
        path = self.table.getModel().getValueAt(row, 3)
        self.view.set_tabbed_pane(self.scanner_pane, self.table, hostname, path, self.issue_name, issue_param)

class Issues:
    scanner_issues = []
    total_count = {}
    issues_count = {}

    def __init__(self):
        self.set_json()
        self.set_issues()

    def set_json(self):
        data_file = os.getcwd() + os.sep + "conf" + os.sep + "issues.json"

        with open(data_file) as data:
            self.json = json.load(data)

    def get_json(self):
        return self.json

    def set_issues(self):
        self.issues = []
        issues = self.json["issues"]

        for vuln_name in issues:
            parameters = issues[vuln_name]["params"]

            for parameter in parameters:
                issue = {
                    "name": str(vuln_name),
                    "param": str(parameter),
                    "count": 0
                }

                self.issues.append(issue)

    def get_issues(self):
        return self.issues

    def set_scanner_issues(self, scanner_issue):
        self.scanner_issues.append(scanner_issue)

    def get_scanner_issues(self):
        return self.scanner_issues

    def check_parameters(self, helpers, parameters):
        vuln_params = []

        for parameter in parameters:
            # Make sure that the parameter is not from the cookies
            # https://portswigger.net/burp/extender/api/constant-values.html#burp.IParameter
            is_not_cookie = parameter.getType() != 2

            if is_not_cookie:
                # Handle double URL encoding just in case
                parameter_decoded = helpers.urlDecode(parameter.getName())
                parameter_decoded = helpers.urlDecode(parameter_decoded)
            else:
                continue

            # TODO: Clean up the gross nested if statements
            # TODO: Think of a better way to store the param_value to be passed on to create_scanner_issues
            # Check to see if the current parameter is a potentially vuln parameter
            for issue in self.issues:
                vuln_param = issue["param"]
                is_vuln_found = re.search(vuln_param, parameter_decoded, re.IGNORECASE)

                if is_vuln_found:
                    is_same_vuln_name = vuln_param == parameter_decoded

                    if is_same_vuln_name:
                        vuln_params.append({
                            "name": issue["name"],
                            "vuln_param": vuln_param,
                            "param": parameter_decoded,
                            "value": parameter.getValue()
                        })
                    else:
                        url = "http://api.pearson.com/v2/dictionaries/ldoce5/entries?headword=" + parameter_decoded
                        response = urllib2.urlopen(url)

                        # Wait a second for response to come back
                        Thread.sleep(1000)

                        data = json.load(response)
                        is_real_word = int(data["count"]) > 0

                        # Checks an English dictionary if parameter is a real word. If it isn't, add it.
                        # Catches: id_param, param_id, paramID, etc.
                        # Does not catch: idea, ideology, identify, etc.
                        if not is_real_word:
                            vuln_params.append({
                                "name": issue["name"],
                                "vuln_param": vuln_param,
                                "param": parameter_decoded,
                                "value": parameter.getValue()
                            })

        return vuln_params

    def create_scanner_issues(self, view, callbacks, helpers, vuln_parameters, request_response):
        issues = self.issues
        json = self.json

        # Takes into account if there is more than one vulnerable parameter
        for vuln_parameter in vuln_parameters:
            issue_name = vuln_parameter["name"]
            vuln_param = vuln_parameter["vuln_param"]
            param_name = vuln_parameter["param"]
            param_value = vuln_parameter["value"]

            url = helpers.analyzeRequest(request_response).getUrl()
            url = urlparse.urlsplit(str(url))
            hostname = url.hostname
            path = url.path
            url = url.scheme + "://" + url.hostname + url.path

            http_service = request_response.getHttpService()
            http_messages = [callbacks.applyMarkers(request_response, None, None)]
            detail = json["issues"][issue_name]["detail"]
            severity = "Medium"

            is_dupe = self.check_duplicate_issue(hostname, issue_name, param_name, param_value)

            if is_dupe:
                continue

            scanner_issue = ScannerIssue(url, issue_name, param_name, vuln_param, param_value, hostname, path, http_service, http_messages, detail, severity, request_response)
            self.set_scanner_issues(scanner_issue)

            issue_count = self.set_issue_count(issue_name, vuln_param)
            total_count = self.total_count[issue_name]

            view.set_scanner_count(issue_name, vuln_param, issue_count, total_count)
            view.set_scanner_table_model(scanner_issue, issue_name, param_name, vuln_param)

    def check_duplicate_issue(self, hostname, issue_name, parameter, value):
        # TODO: Change to scanner_issues
        issues = self.get_scanner_issues()

        for issue in issues:
            url = urlparse.urlsplit(str(issue.getUrl()))
            is_same_hostname = hostname == url.hostname
            is_same_issue_name = issue_name == issue.getIssueName()
            is_same_parameter = parameter == issue.getParameter()
            is_same_value = value == issue.getParameterValue()
            is_dupe = is_same_hostname and is_same_parameter and is_same_issue_name and is_same_value

            if is_dupe:
                return True

        return False

    def set_issue_count(self, issue_name, issue_param):
        for issue in self.issues:
            is_name = issue["name"] == issue_name
            is_param = issue["param"] == issue_param
            is_issue = is_name and is_param

            if is_issue:
                issue["count"] += 1
                is_total_key_exists = issue_name in self.total_count

                if is_total_key_exists:
                    self.total_count[issue_name] += 1
                else:
                    self.total_count[issue_name] = 1

                key = issue_name + "." + issue_param
                is_issue_key_exists = key in self.issues_count

                if is_issue_key_exists:
                    self.issues_count[key] += 1
                else:
                    self.issues_count[key] = 1

                return issue["count"]

    def get_issues_count(self, issue_name, issue_param):
        key = issue_name + "." + issue_param
        return self.issues_count[key]

    def change_issues_count(self, issue_name, issue_param, is_checked):
        key = issue_name + "." + issue_param

        if is_checked:
            self.issues_count[key] -= 1
        else:
            self.issues_count[key] += 1

    def get_total_count(self, issue_name):
        return self.total_count[issue_name]

    def change_total_count(self, issue_name, is_checked):
        if is_checked:
            self.total_count[issue_name] -= 1
        else:
            self.total_count[issue_name] += 1

# TODO: Fill out all the getters with proper returns
class ScannerIssue(IScanIssue):
    def __init__(self, url, issue_name, parameter, vuln_param, param_value, hostname, path, http_service, http_messages, detail, severity, request_response):
        self._url = url
        self._http_service = http_service
        self._http_messages = http_messages
        detail = detail.encode("utf-8")
        self._detail = detail.replace("$param$", parameter.encode("utf-8"))
        self._current_severity = severity
        self._request_response = request_response
        self._issue_background = ""
        self._issue_name = issue_name
        self._parameter = parameter
        self._vuln_param = vuln_param
        self._hostname = hostname
        self._path = path
        self._param_value = param_value
        self._remediation_background = ""

    def getRequestResponse(self):
        return self._request_response

    def getVulnParameter(self):
        return self._vuln_param

    def getParameter(self):
        return self._parameter

    def getParameterValue(self):
        return self._param_value

    def getHostname(self):
        return self._hostname

    def getPath(self):
        return self._path

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issue_name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._current_severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return self._issue_background

    def getRemediationBackground(self):
        return self._remediation_background

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

if __name__ in ('__main__', 'main'):
    EventQueue.invokeLater(Run(BurpExtender))
