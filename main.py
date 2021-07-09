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

def collect_ifPorts(connection: snmp_conn_obj, allowed_types: tuple = (6, 56), skip_if_down: bool = True) -> dict:
    """
    OIDs
    1.3.6.1.2.1.2.2.1.1 #ifIndex
    1.3.6.1.2.1.2.2.1.2 #ifDescr
    1.3.6.1.2.1.2.2.1.3 #ifType
    1.3.6.1.2.1.2.2.1.8 #ifOperStatus (1 = up, 2 = down)
    """
    
    ifPorts = {}
    q_ifIndexes = snmp_get.walk_objid(connection, "ifIndex")
    
    for id in q_ifIndexes.values():
        
        # check if physical port
        ifType = snmp_get.get_objid(connection, "ifType." + str(id))
        # skip port if by default not an ethernet or fibre channel
        # see all types here https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        
        if skip_if_down:
            # check if link is up (optional)
            ifOperStatus = snmp_get.get_objid(connection, "ifOperStatus." + str(id))
            # skip port if link is down
            if ifOperStatus == 2:
                continue
        
        ifPorts[id] = snmp_get.get_objid(connection, "ifDescr." + str(id))
        
    return ifPorts

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
       
def collect_machines(connection: snmp_conn_obj) -> set:
    # http://oid-info.com/get/1.3.6.1.2.1.2.2.1.3
    ifPorts = collect_ifPorts(connection, allowed_types=('*'), skip_if_down=False)
    bPort_to_ifPort = collect_bPorts(connection)
    
    """
    # get learned macs and assosciate to phy port
    1.3.6.1.2.1.17.4.3.1.1 #dot1dTpFdbAddress
    1.3.6.1.2.1.17.4.3.1.3 #dot1dTpFdbStatus (3 = learned, 4 = self)
    1.3.6.1.2.1.17.4.3.1.2 #dot1dTpFdbPort (bridgebaseIndex)
    """
    devices = set()
    macs_on_bridge = snmp_get.walk_objid(connection, "1.3.6.1.2.1.17.4.3.1.1")
    for mac in macs_on_bridge.values():
        
        # check if valid table entry
        mac_status = snmp_get.get_objid(connection, "1.3.6.1.2.1.17.4.3.1.3." + ".".join(map(str,mac)))
        # skip if MAC is not learned or static configuration
        if mac_status != 3 and mac_status != 4:
            continue
        
        # get bPort
        mac_bport = snmp_get.get_objid(connection, "1.3.6.1.2.1.17.4.3.1.2." + ".".join(map(str,mac)))
        
        # make device
        if mac_bport in bPort_to_ifPort and bPort_to_ifPort[mac_bport] in ifPorts:
            devices.add(machine(mac, '', connection.address,
                               bPort_to_ifPort[mac_bport], ifPorts[bPort_to_ifPort[mac_bport]]))
        
    return devices
    
    # check out vlans
    #print(snmp_get.walk_objid(connection, "1.3.6.1.2.1.17.7.1.4.3.1.1"))
    
def main():
    conn = snmp_conn_obj("10.161.56.25")
    conn2 = snmp_conn_obj("10.161.56.30")
    
    machines0 = collect_machines(conn)
    machines1 = collect_machines(conn2)
    
    print("Symmetric Difference: ", machines0.symmetric_difference(machines1))
    print("Intersection: ", machines0.intersection(machines1))
    
    
if __name__ == "__main__":
    sys.exit(main())
