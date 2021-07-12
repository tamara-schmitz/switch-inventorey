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
import create_graphs

def collect_ifPorts(sw: Switch, allowed_types: tuple = ('*'), filtered_types: tuple = (), skip_if_down: bool = True) -> Switch:
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
        
        # check port type
        ifType = snmp_get.get_objid(sw.connection, "ifType." + str(id))
        # see all types here https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        if ifType in filtered_types:
            continue
        
        if skip_if_down:
            ifOperStatus = snmp_get.get_objid(sw.connection, "ifOperStatus." + str(id))
            if ifOperStatus == 2:
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

def collect_iptable(connection: snmp_conn_obj, table : dict = {}) -> dict:
    q_iptable_mac = snmp_get.walk_objid(connection, "1.3.6.1.2.1.4.22.1.2")
    q_iptable_ip = snmp_get.walk_objid(connection, "1.3.6.1.2.1.4.22.1.3")
    
    if len(q_iptable_ip) == len(q_iptable_mac):
        table_mac_iter = iter(q_iptable_mac.values())
        table_ip_iter = iter(q_iptable_ip.values())
        for mac in table_mac_iter:
            table[mac] = next(table_ip_iter)
    
    print(table)
    return table
    
def collect_devices(sw: Switch, query_hostname=True) -> Switch:
    # http://oid-info.com/get/1.3.6.1.2.1.2.2.1.3
    collect_ifPorts(sw, allowed_types=(6, 56, 161))
    for port in sw.ports.values():
        if port.mac != MAC((0, 0, 0, 0, 0, 0)):
            sw.macs.append(port.mac)

    bPort_to_ifPort = collect_bPorts(sw.connection)
    if query_hostname:
        mac_to_ip = collect_iptable(sw.connection)
    
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
            
        mac_hostname = ""
        if query_hostname:
            if mac in mac_to_ip:
                mac_hostname = mac_to_ip[mac]
        
        if mac_ifport in sw.ports:
            # TODO switch detection
            sw.ports[mac_ifport].nodes.add(Node(mac, mac_hostname, False))
            
    return sw
    
def main():
    switch0 = Switch("Mellanox", [], {}, snmp_conn_obj("10.161.56.25"))
    switch1 = Switch("Cisco", [], {}, snmp_conn_obj("10.161.56.30"))
    
    collect_devices(switch0)
    collect_devices(switch1)
    
    graph = create_graphs.switch_to_graph(switch0)
    graph = create_graphs.switch_to_graph(switch1, graph)
    
    graph.format='png'
    graph.render('test-graph')
    
    #print(switch0.ports)
    #print(switch1.ports)
    
if __name__ == "__main__":
    sys.exit(main())
