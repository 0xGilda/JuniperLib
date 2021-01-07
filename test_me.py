#!/usr/bin/env python

import sys

import JunosNetconf

jnc = JunosNetconf.JunosNetconf()
dev = jnc.GetNetconfInterface('TL1-vMX-168',user='jnpr')
xml_results =  jnc.GetCliCommandJunos(dev, 'show route', output='xml')
if jnc.VerifyElementInXML(xml_results, sys.argv[1]):
    print("Found element")
else:
    print("Did not find element")
jnc.ShutNetconfInterface(dev)

