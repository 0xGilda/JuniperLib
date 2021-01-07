import json
from lxml import etree, objectify
from jnpr.junos import Device
from jnpr.junos.exception import *
from jnpr.junos.utils.config import Config

import logging
import pprint

logger = logging.getLogger(__name__)


class JunosNetconf:

    """ CONSTANTS """
    XML_RPC_BEGIN = "<rpc-reply xmlns:junos"
    XML_RPC_END = "</rpc-reply>"
    XSLT_TRANSFORM = '''
                        <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                        <xsl:output method="xml" indent="no"/>
                        <xsl:template match="/|comment()|processing-instruction()">
                            <xsl:copy>
                                <xsl:apply-templates/>
                            </xsl:copy>
                        </xsl:template>
                        <xsl:template match="*">
                            <xsl:element name="{local-name()}">
                                <xsl:apply-templates select="@*|node()"/>
                            </xsl:element>
                        </xsl:template>
                        <xsl:template match="@*">
                            <xsl:attribute name="{local-name()}">
                                <xsl:value-of select="."/>
                            </xsl:attribute>
                        </xsl:template>
                        </xsl:stylesheet>
                     '''
    
    def __str__(self):
        """Generate a user readable representation of object for debug outputs"""
        return "NorthStarRest(host=" + self.host + ",username=" + self.username + ",password=" + self.password + ")"
    
    def __init__(self, host, user=None, password=None):
        self.host = host
        self.username = user
        self.password = password
        self.connected = False
        self.config = None
        self.configPrivate = False
        self.configExclusive = False
        self.configDynamic = False
        self.configBatch = False

    def _authenticate(self, username, password):
        self.username = username
        logger.debug("NETCONF _authenticate: username = " + username)

        if password:
            self.password = password
            logger.debug("NETCONF _authenticate: password = " + password)
        else:
            logger.debug("NETCONF _authenticate: using ssh key authentication")

        dev = Device(self.host, user=username, password=password, auto_probe=15)
        try:
            dev.open()
        except Exception as err:
            logger.debug("NETCONF _authenticate: Failed to open connection with error: " + str(err))
            return

        dev.timeout = 900
        self.dev = dev
        self.connected = True
        return

    def op(self, op, obj=None, objParams=[], *args, **kwargs):
        """
          Do a NETCONF operation
           - op is an internal operation type:
              - config       : get entire configuration
              - text         : send command to router and return output in normal human readable format
              - xml          : send command to router and return output in XML format
              - json         : send command to router and return output in JSON format
              - configure    : start a configuration change
              - merge        : merge configuration with the existing configuration
              - override     : replace the entire configuration with the provided configuration
              - replace      : merge configuration with existing configuration but replace existing configuration with those that specify the replace: tag
              - delete       : delete configuration
              - commit       : commit configuration
           - obj is the object (command, configuration, etc.)
             obj should be command without display options or configuration should be single line configuration statement without set or delete
           - objParams are any options needed (i.e. pipe options (match and etc.) for commands or exclusive/private mode for configure option)
        """
        logger.debug("NETCONF op: " + op + ' ' + pprint.pformat(obj) + ' objParams=' + pprint.pformat(objParams) + ' kwargs=' + pprint.pformat(kwargs))
        # pprint.pprint(obj)
        # pprint.pprint(objParams)
        # pprint.pprint(reqParams)

        # Return the entire configuration in XML format
        if op == "config":
            try:
                result = self.dev.rpc.get_config()
            except Exception as err:
                return {"status_code": "fail", "result": err.message}

            # Cleanup XML configuration returned to print to debug log
            parser = etree.XMLParser(remove_blank_text=True)
            contents = etree.tostring(result)
            xmlDebug = etree.fromstring(contents, parser=parser)
            logger.debug("NETCONF op: XML configuration returned:")
            logger.debug(etree.tostring(xmlDebug, pretty_print=True, encoding="unicode"))
            
            return {"status_code": "success", "result": result}
        
        # Execute the given cli command and return the requested format
        if op in ['text','json','xml']:
            # Get the RPC mapping for the given command
            rpcXml = self.dev.display_xml_rpc(obj, format="text")
            rpcLines = rpcXml.splitlines()
            rpcCall = rpcLines[0].replace("-","_")
            rpcCall = rpcCall[1:-1]
            
            for arg in args:
                if arg == "extensive":
                    kwargs["level"] = "extensive"
            
            try:
                if op == "xml":
                    result = getattr(self.dev.rpc, rpcCall)(normalize=True,**kwargs)
                else:
                    result = getattr(self.dev.rpc, rpcCall)({'format':op},**kwargs)
            except Exception as err:
                return {"status_code": "fail", "result": err.message}
            
            # Get text output out of XML tag
            if op == "text":
                result = result.text.strip()
            
            # Print results in debug log
            if not kwargs.has_key("noDebug") or kwargs['noDebug'] is False:
                if op == "xml":
                    parser = etree.XMLParser(remove_blank_text=True)
                    contents = etree.tostring(result)
                    xmlDebug = etree.fromstring(contents, parser=parser)
                    logger.debug("NETCONF op: CLI command returned:\n" + etree.tostring(xmlDebug, pretty_print=True, encoding="unicode"))
                if op == "json":
                    logger.debug("NETCONF op: CLI command returned:\n" + json.dumps(result, indent=4))
                if op == "text":
                    logger.debug("NETCONF op: CLI command returned:\n" + result)
            
            return {"status_code": "success", "result": result}
        
        # Start a configuration change by setting up class variables (configuration changes are started and committed in one atomic operation on the router through the commit operation)    
        if op == "configure":
            self.mergeConfig = ""
            self.overrideConfig = ""
            self.replaceConfig = ""
            self.configMode = None
            
            for param in objParams:
                if param in ['exclusive','private','dynamic','batch']:
                    if self.configMode == None:
                        self.configMode = param
                        logger.debug("NETCONF op: configure mode is " + param)
                    else:
                        logger.info("NETCONF op: ignoring extra configure mode option: " + param)
                    
        # Add configuration provided to full configuration
        if op == "merge":
            self.mergeConfig += "set " + obj + "\n"
        if op == "override":
            self.overrideConfig += "set " + obj + "\n"
        if op == "replace":
            self.replaceConfig += "set " + obj + "\n"
        if op == "delete":
            self.replaceConfig += "delete " + obj + "\n"
                
        # Commit configuration provided using the options given when configure was called
        if op == "commit":
            # Context manager will lock and unlock the configuration for us as needed
            with Config(self.dev,mode=self.configMode) as cu:
                logger.debug("NETCONF op: Config object created with mode " + self.configMode)

                # Add each type of configuration change to the commit(merge, override, replace, and update)
                if self.mergeConfig:
                    logger.info("NETCONF op: Load merge configuration:\n" + self.mergeConfig)
                    try:
                        cu.load(self.mergeConfig,merge=True,format='set')
                    except (ValueError,ConfigLoadError) as err:
                        return {"status_code": "fail", "result": err.message}
                    except Exception as err:
                        if err.rsp.find(".//ok") is None:
                            rpcMsg = err.rsp.fintext(".//error-message")
                            return {"status_code": "fail", "result": rpcMsg}                   
                if self.overrideConfig:
                    logger.info("NETCONF op: Load override configuration:\n" + self.overrideConfig)
                    try:
                        cu.load(self.overrideConfig,overwrite=True,format='set')
                    except (ValueError,ConfigLoadError) as err:
                        return {"status_code": "fail", "result": err.message}
                    except Exception as err:
                        if err.rsp.find(".//ok") is None:
                            rpcMsg = err.rsp.fintext(".//error-message")
                            return {"status_code": "fail", "result": rpcMsg}
                if self.replaceConfig:
                    logger.info("NETCONF op: Load replace configuration:\n" + self.replaceConfig)
                    try:
                        cu.load(self.replaceConfig,format='set')
                    except (ValueError,ConfigLoadError) as err:
                        return {"status_code": "fail", "result": err.message}
                    except Exception as err:
                        if err.rsp.find(".//ok") is None:
                            rpcMsg = err.rsp.fintext(".//error-message")
                            return {"status_code": "fail", "result": rpcMsg}
                    
                # Commit the configurations
                try:
                    cu.commit()
                except CommitError as err:
                    return {"status_code": "fail", "result": err.message}

        return {"status_code": "success", "result": ""}

def __testMe():
     pass
#     pcsIp = '172.25.157.239'
#     username = 'admin'
#     password = 'admin1'
#     sslport = '8443'
#     port = "8091"
#     auth = True
# 
#     r = NorthStarNoneRest(pcsIp, port, sslport, username, password, auth)
#     restUrl = "/NorthStar/API/v2/tenant/1/topology/1/nodes/"
#     # operation = "GET"
#     # print r.op(operation,restUrl)
#     # restUrl=""
#     # operation="post"
#     # jsonData= {"name": "test1111111111111", "from": {"topoObjectType":"ipv4","address": "11.0.0.102"},"to": {"address": "11.0.0.104","topoObjectType":"ipv4"}}
#     # jsonData= {"name": "vmx101","topoObjectType": "node","topologyIndex": 1}
#     #
#     # print r.op(operation,restUrl,jsonData)
#     jsonData = """[{"name": "Rest_LSP_1","from": {"topoObjectType": "ipv4","address": "11.0.0.101" },"to": {"topoObjectType": "ipv4","address": "11.0.0.103"  },"pathType": "primary","plannedProperties": {"bandwidth": "15M","setupPriority": 7,"holdingPriority": 7	}},{"name": "Rest_LSP_2","from": {"topoObjectType": "ipv4","address": "11.0.0.101" },"to": {"topoObjectType": "ipv4","address": "11.0.0.103"  },"pathType": "primary","plannedProperties": {"bandwidth": "1M","setupPriority": 7,"holdingPriority": 7	}}]"""
#     restUrl = "/NorthStar/API/v2/tenant/1/topology/1/te-lsps/bulk"
#     operation = "post"
#     print r.op(operation, restUrl, jsonData),
#     # restUrl=""
#     # operation = "UPDATE"
#     # print r.op(operation,restUrl)
#     # restUrl=""
#     # operation = "DELETE"
#     # print r.op(operation,restUrl)
#     pass


if __name__ == "__main__":
    __testMe()
