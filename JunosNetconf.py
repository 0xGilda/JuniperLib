from datetime import datetime
import re

import JunosNetconfUtils
import JuniperPassword
import jxmlease
from lxml import etree, objectify

import paramiko
from robot.libraries.BuiltIn import BuiltIn

robot = BuiltIn()

class JunosNetconf(object):
    ROBOT_LIBRARY_SCOPE = 'TEST SUITE'
    ROBOT_LIBRARY_VERSION = 1.0

    """ CONSTANTS """
    TIMESTAMP_RE = re.compile("\\w{3} *\\d{1,2} *\\d{1,2}:\\d{1,2}:\\d{1,2}")

    def __init__(self,*args):
        self._debugFlag=False
        for arg in args:
            if re.match("^DEBUG=1",arg):
                self._debugFlag=True
        self._netconfIf={}


    def Decrypt9(self,password):
        return JuniperPassword.decrypt9(password)


    def GetNetconfInterface(self,host,user=None,password=None):
        trackingKey=str((host,user,password))
        if self._netconfIf.has_key(trackingKey):
            return self._netconfIf[trackingKey]
        ret = JunosNetconfUtils.JunosNetconf(host)
        self._netconfIf[trackingKey]=ret
        ret._authenticate(user,password)
        if not ret.connected:
          raise RuntimeError("Error: NETCONF login failed on host " + host)
        return ret

    def ShutNetconfInterface(self,netconf):
        if netconf.dev is not None:
            netconf.dev.close()
        trackingKey=str((netconf.host,netconf.username,netconf.password))
        if self._netconfIf.has_key(trackingKey):
            self._netconfIf.pop(trackingKey)

    
    def GetJunosConfiguration(self,netconf,save=None):
        result = netconf.op("config")
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF get configuration failed with " + result["result"] + " on host " + netconf.host)
        return result["result"]

    
    def GetCliCommandJunos(self,netconf,command,params=[],output="xml",save=None,*args,**kwargs):
        result = netconf.op(output,command,objParams=params,*args,**kwargs)
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF get CLI command failed with " + result["result"] + " on host " + netconf.host)
        return result["result"]


    def GetSshCommandJunos(self,host,user,password,command,save=None):
        if password[:3] == "$9$":
            password = JuniperPassword.decrypt9(password)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        ssh.connect(host,username=user,password=password)
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
        ssh_stdout = ssh_stdout.readlines()
        result = ""
        for line in ssh_stdout:
            result += line
        return result

    
    def GetRouteTableTotalCountJunos(self,netconf,tableName,save=None):
        # Get route table information
        commandOutput = self.GetCliCommandJunos(netconf,"show route summary", output="xml")
        
        # Find given route table and return the total-route-count
        routeTableList = commandOutput.findall("route-table")
        for routeTable in routeTableList:
            if routeTable.find("table-name").text == tableName:
                return int(routeTable.find("total-route-count").text)
        raise RuntimeError("Error: Routing table " + str(tableName) + " not found on host " + str(netconf.host))
    
    
    def GetRouteTableActiveCountJunos(self,netconf,tableName,save=None):
        # Get route table information
        commandOutput = self.GetCliCommandJunos(netconf,"show route summary", output="xml")
        
        # Find given route table and return the total-route-count
        routeTableList = commandOutput.findall("route-table")
        for routeTable in routeTableList:
            if routeTable.find("table-name").text == tableName:
                return int(routeTable.find("active-route-count").text)
        raise RuntimeError("Error: Routing table " + str(tableName) + " not found on host " + str(netconf.host))
        
    def VerifyLspJunos(self,netconf,lspName,save=None,**kwargs):
        """
        Verify an LSP on Junos using XML RPC calls and PyEZ.  kwargs are values to check on the LSP and supported values are below:
        
            bandwidth
            hold
            setup
            fastReroute (value is true or false as string)
            lspType (value is external or local as string)
        """
        # Get CLI command output
        commandOutput = self.GetCliCommandJunos(netconf, "show mpls lsp", output="xml", level="extensive")
        
        # Verify LSP and if verification fails then throw a RuntimeError to fail the test
        result = self._verifyLsp(netconf.host, commandOutput, lspName, **kwargs)
        if result is False:
            raise RuntimeError("ERROR: LSP failed validation")
        else:
            robot.log("\n### Verified that LSP {!s} on host {!s} exists and is up".format(lspName, netconf.host),console=True)
        
    
    def VerifyBulkLspJunos(self,netconf,lspNameList,save=None,**kwargs):
        """
        Verify a list of LSPs on Junos using XML RPC calls and PyEZ.  kwargs are values to check on the LSP and supported values are below:
        
            bandwidth
            hold
            setup
            fastReroute (value is true or false as string)
            lspType (value is external or local as string)
            
        Returns the number of LSPs that were verified successfully.
        """
        # Get CLI command output
        commandOutput = self.GetCliCommandJunos(netconf, "show mpls lsp", output="xml", level="extensive")
        
        # Verify each LSP in the list given and keep track of how many pass validation
        validated = 0
        for lspName in lspNameList:
            result = self._verifyLsp(netconf.host, commandOutput, lspName, log=False, **kwargs)
            if result is True:
                validated += 1
        
        robot.log("\n### Verified {!s} of {!s} LSPs on the PCC at {!s}".format(validated,len(lspNameList),netconf.host),console=True)
        return validated
          
    def VerifyBgpPeeringJunos(self,netconf,neighbor,save=None):
        # Get CLI command output
        commandOutput = self.GetCliCommandJunos(netconf, "show bgp summary", output="xml")
        
        # Find the right BGP peering and check if peering is established and return if success
        bgpPeerList = commandOutput.findall("bgp-peer")
        for bgpPeer in bgpPeerList:
            if bgpPeer.find("peer-address").text == neighbor:
                if bgpPeer.find("peer-state").text == "Established":
                    return
                else:
                    raise RuntimeError("Error: BGP peering is down for neighbor " + neighbor + " on host " + netconf.host)
                
        # BGP peering was not found so generate an error
        raise RuntimeError("Error: BGP peering not found for neighbor " + neighbor + " on host " + netconf.host)
    
    
    def VerifyBgpFullMeshPeeringJunos(self,netconfList,save=None):
        # Determine list of hosts to verify BGP peerings on
        hostIpList = []
        for netconf in netconfList:
            hostIpList.append(netconf.host)
            
        # Check BGP peerings for each combination of hosts
        for netconf in netconfList:
            for neighbor in hostIpList:
                if netconf.host == neighbor:
                    continue
                else:
                    self.VerifyBgpPeeringJunos(netconf,neighbor)
    
    def VerifyProcessRunningJunos(self,netconf,processName,save=None):
        # Get process information using SSH connection as show system process has no XML RPC equivalent
        commandOutput = self.GetSshCommandJunos(netconf.host, netconf.username, netconf.password, "show system processes", save)
        robot.log("VerifyProcessRunningJunos: commandOutput:\n" + str(commandOutput),"DEBUG")
        
        # Check to see if the given process is in the output
        if processName not in commandOutput:
            raise RuntimeError("Error: Process " + str(processName) + " is not running on Junos device " + str(netconf.host))
        return commandOutput

    def GetLspRroJunos(self,netconf,lspName,pathName=None,save=None,**kwargs):
        # Get CLI command output
        commandOutput = self.GetCliCommandJunos(netconf, "show mpls lsp",output="xml",level="extensive",regex=lspName)
        
        # Extract the information if an LSP was returned in the output
        sessionList = []
        sessionGroupList = commandOutput.findall("rsvp-session-data")
        for sessionGroup in sessionGroupList:
            sessionList.extend(sessionGroup.findall("rsvp-session"))
            
        if len(sessionList) == 0:
            raise RuntimeError("Error: LSP named " + lspName + " was not found on PE " + netconf.host)
            return
        session = sessionList[0]
        if session.find("mpls-lsp") is not None:
            lsp = session.find("mpls-lsp")
        else:
            lsp = session
        
        # Find the correct RRO using the path name
        if pathName is None:
            rroOutput = lsp.find("mpls-lsp-path").find("received-rro").text
        else:
            rroOutput = None
            pathList = lsp.findall("mpls-lsp-path")
            for path in pathList:
                if path.find("name").text == pathName:
                    rroOutput = path.find("received-rro").text
        
        # If path wasn't found trigger runtime error and indicate path was not found
        if rroOutput is None:
            raise RuntimeError("Error: NETCONF get RRO failed path " + str(pathName) + " was not found for LSP " + str(lspName) + " on host " + str(netconf.host))
        
        # Need to clean up rro output from Junos so we only have the IP address list
        rroRaw = rroOutput.split(":")[1].strip()
        search = re.compile("(?:(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?:\\((.*?)\\))?)")
        matches = search.findall(rroRaw)
        result = ""
        for match in matches:
            # If RRO entry contains flags in () then check for a label and include in RRO as entry is a next hop and drop entry if no label as it is a node entry
            if len(match) == 1:
                result += match + " "
            else:
                hop, flags = match
                if "label" not in flags:
                    if kwargs.has_key("nodes") and kwargs["nodes"] == False:
                        continue
                result += hop + " "
        return result.strip()

    
    def DeleteConfigurationJunos(self,netconf,configurationList,mode,save=None):
        result = netconf.op("configure",objParams=[mode])
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF configure op failed with " + result['result'] + " on host " + netconf.host)
        for configuration in configurationList:
            result = netconf.op("delete",configuration)
            if result['status_code'] == "fail":
                raise RuntimeError("Error: NETCONF delete op failed with " + result['result'] + " on host " + netconf.host)
        result = netconf.op("commit")
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF commit op failed with " + result['result'] + " on host " + netconf.host)

     
    def MergeConfigurationJunos(self,netconf,configurationList,mode,save=None):
        result = netconf.op("configure",objParams=[mode])
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF configure op failed with " + result['result'] + " on host " + netconf.host)
        for configuration in configurationList:
            result = netconf.op("merge",configuration)
            if result['status_code'] == "fail":
                raise RuntimeError("Error: NETCONF merge op failed with " + result['result'] + " on host " + netconf.host)
        result = netconf.op("commit")
        if result['status_code'] == "fail":
            raise RuntimeError("Error: NETCONF commit op failed with " + result['result'] + " on host " + netconf.host)
        
        
    def _verifyLsp(self,host,commandOutput,lspName,**kwargs):
        # Find the right LSP and check if state is up
        sessionGroupList = commandOutput.findall("rsvp-session-data")
        for sessionGroup in sessionGroupList:
            #robot.log("_verifyLsp: session-type = {!r}".format(sessionGroup.find("session-type").text),"DEBUG")
            if sessionGroup.find("session-type") is None or sessionGroup.find("session-type").text != "Ingress":
                continue
            sessionList = sessionGroup.findall("rsvp-session")
            for session in sessionList:
                if session is None:
                    continue
                if session.find("mpls-lsp") is not None:
                    lsp = session.find("mpls-lsp")
                else:
                    lsp = session
                #robot.log("_verifyLsp: lsp name = {!r}".format(lsp.find("name").text),"DEBUG")
                if lsp.find("name").text == lspName:
                    parser = etree.XMLParser(remove_blank_text=True)
                    contents = etree.tostring(lsp)
                    xmlDebug = etree.fromstring(contents, parser=parser)
                    robot.log("Verify LSP Junos: LSP XML:\n" + etree.tostring(xmlDebug, pretty_print=True, encoding="unicode"),"DEBUG")
                    
                    # Check values on LSP that were given in kwargs
                    for k in ['bandwidth','setup','hold','fastReroute','lspType']:
                        if not kwargs.has_key(k):
                            continue
                        errorString = ""
                        netconfData = None
                        if k == "bandwidth":
                            errorString = "bandwidth"
                            # For bandwidth = 0 then no bandwidth entry exists
                            if lsp.find("mpls-lsp-path").find("bandwidth") is not None:
                                netconfData = lsp.find("mpls-lsp-path").find("bandwidth").text
                            else:
                                netconfData = "0"
                        elif k == "setup":
                            errorString = "setup priority"
                            netconfData = lsp.find("mpls-lsp-path").find("setup-priority").text
                        elif k == "hold":
                            errorString = "hold priority"
                            netconfData = lsp.find("mpls-lsp-path").find("setup-priority").text
                        elif k == "fastReroute":
                            errorString = "fast reroute"
                            if lsp.find("is-fastreroute") is not None:
                                netconfData = "true"
                            else:
                                netconfData = "false"
                        elif k == "lspType":
                            errorString = "lsp type"
                            netconfData = "local"
                            if "Externally controlled" in lsp.find("lsp-type").text:
                                if "Externally controlled" in lsp.find("lsp-control-status"):
                                    netconfData = "external"
                            
                        #Test value and if not equal raise runtime error indicating which value failed
                        if netconfData != kwargs[k]:
                            robot.log("NETCONF LSP " + errorString + " response " + str(netconfData) + " does not match expected response " + str(kwargs[k]),"ERROR")
                            return False
                        else:
                            if not kwargs.has_key("log") or kwargs['log'] == True:
                                robot.log("\n### Verified LSP {!s} {!s} set to {!s}".format(lspName,errorString,netconfData),console=True)
                     
                    # Check LSP state   
                    if lsp.find("lsp-state").text == "Up":
                        return True
                    else:
                        robot.log("LSP named " + lspName + " is down on PE " + host,"ERROR")
                        return False
                    
        robot.log("LSP named " + lspName + " was not found on PE " + host,"ERROR")
        return False

    def VerifyElementInXML(self, xml, element):
        """ Returns true if element exists in table 
            xml = lxml.Element
            element = string representation of element
        """
        print("type of xml: {}".format(type(xml)))
        print("type of element: {}".format(type(element)))

        if xml.xpath('//' + element):
            return True
        else:
            return False

#    def GetJxmlease(self, xml):
#        parser = jxmlease.Parser()
#        return parser(xml)
        
