#!/usr/bin/python3

import platform
py_ver = platform.python_version_tuple()
if not (int(py_ver[0]) >= 3 and int(py_ver[1]) >= 7):
    print("This script requires Python version 3.7 or higher!")
    exit()

import os
import shutil
from pathlib import Path
import textwrap
import argparse
import sys

from dataclass_defines import *
import snmp_get

def collect_ifPorts(sw: Switch, allowed_types: tuple = (6, 56), skip_if_down: bool = True) -> Switch:
    """
    OIDs
    1.3.6.1.2.1.2.2.1.1 #ifIndex
    1.3.6.1.2.1.2.2.1.2 #ifDescr
    1.3.6.1.2.1.2.2.1.3 #ifType
    1.3.6.1.2.1.2.2.1.6 #ifPhysAddress
    1.3.6.1.2.1.2.2.1.8 #ifOperStatus (1 = up, 2 = down)
    """
    
    sw.ports = {}
    
    q_ifIndexes = snmp_get.walk_objid(sw.connection, "ifIndex")
    for id in q_ifIndexes.values():
        ifPhyAddr = snmp_get.get_objid(sw.connection, "ifPhysAddress." + str(id))
        ifDescr = snmp_get.get_objid(sw.connection, "ifDescr." + str(id))
        
        # check if physical port
        ifType = snmp_get.get_objid(sw.connection, "ifType." + str(id))
        # skip port if by default not an ethernet or fibre channel
        # see all types here https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        
        ifOperStatus = snmp_get.get_objid(sw.connection, "ifOperStatus." + str(id))
        if skip_if_down and ifOperStatus == 2:
                continue
        
        sw.ports[id] = SPort(id, ifDescr, MAC(ifPhyAddr), ifOperStatus == 2, set(), "")
        
    return sw

def collect_bPorts(connection: snmp_conn_obj) -> dict:
    """
    1.3.6.1.2.1.17.1.4.1.1 #dot1dBasePort
    1.3.6.1.2.1.17.1.4.1.2 #dot1dBasePortIfIndex
    """
    bPort_to_ifPort = {}
    q_bridge_indexes = snmp_get.walk_objid(connection, "1.3.6.1.2.1.17.1.4.1.1")
    for bport in q_bridge_indexes.values():
        bPort_to_ifPort[bport] = snmp_get.get_objid(connection, "1.3.6.1.2.1.17.1.4.1.2." + str(bport))
    
    return bPort_to_ifPort
       
def collect_devices(sw: Switch) -> Switch:
    # http://oid-info.com/get/1.3.6.1.2.1.2.2.1.3
    collect_ifPorts(sw, allowed_types=('*'), skip_if_down=True)
    for port in sw.ports.values():
        if port.mac != MAC((0, 0, 0, 0, 0, 0)):
            sw.macs.append(port.mac)

    bPort_to_ifPort = collect_bPorts(sw.connection)
    
    """
    # get learned macs and assosciate to phy port
    1.3.6.1.2.1.17.4.3.1.1 #dot1dTpFdbAddress
    1.3.6.1.2.1.17.4.3.1.3 #dot1dTpFdbStatus (3 = learned, 4 = self)
    1.3.6.1.2.1.17.4.3.1.2 #dot1dTpFdbPort (bridgebaseIndex)
    """
    macs_on_bridge = snmp_get.walk_objid(sw.connection, "1.3.6.1.2.1.17.4.3.1.1")
    for mac in macs_on_bridge.values():
        # check if valid table entry
        mac_status = snmp_get.get_objid(sw.connection, "1.3.6.1.2.1.17.4.3.1.3." + mac.as_decstr())
        # skip if MAC is not learned or static configuration
        if mac_status != 3 and mac_status != 4:
            continue
        
        mac_bport = snmp_get.get_objid(sw.connection, "1.3.6.1.2.1.17.4.3.1.2." + mac.as_decstr())
        
        mac_ifport = None
        if mac_bport in bPort_to_ifPort:
            mac_ifport = bPort_to_ifPort[mac_bport]
        
        if mac_ifport in sw.ports:
            sw.ports[mac_ifport].nodes.add(Node(mac, "", False))
        
    return sw
    
    # check out vlans
    #print(snmp_get.walk_objid(connection, "1.3.6.1.2.1.17.7.1.4.3.1.1"))
    
def main():
    switch0 = Switch("Mellanox", [], {}, snmp_conn_obj("10.161.56.25"))
    switch1 = Switch("Cisco", [], {}, snmp_conn_obj("10.161.56.30"))
    
    collect_devices(switch0)
    collect_devices(switch1)
    
    print(switch0.ports)
    print(switch1.ports)
    
    
if __name__ == "__main__":
    sys.exit(main())
