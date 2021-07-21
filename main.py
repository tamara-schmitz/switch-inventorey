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
import easysnmp

from dataclass_defines import *
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
    sw.connection.use_sprint_value = True
    
    q_ifIndexes = sw.connection.walk("ifIndex")
    for id in q_ifIndexes:
        id = id.value
        
        ifPhyAddr = sw.connection.get("ifPhysAddress." + str(id)).value
        ifDescr = sw.connection.get("ifDescr." + str(id)).value
        
        # check port type
        ifType = sw.connection.get("ifType." + str(id)).value
        # see all types here https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        if ifType in filtered_types:
            continue
        
        ifOperStatus = sw.connection.get("ifOperStatus." + str(id)).value
        if skip_if_down:
            if 'down' in ifOperStatus:
                continue
        
        sw.ports[id] = SPort(id, ifDescr, MAC(ifPhyAddr), 'up' in ifOperStatus, set(), "")
        
    return sw

def collect_bPorts(connection: snmp_conn_obj) -> dict:
    """
    1.3.6.1.2.1.17.1.4.1.1 #dot1dBasePort
    1.3.6.1.2.1.17.1.4.1.2 #dot1dBasePortIfIndex
    """
    connection.use_sprint_value = True
    bPort_to_ifPort = {}
    q_bridge_indexes = connection.walk("1.3.6.1.2.1.17.1.4.1.1")
    for bport in q_bridge_indexes:
        bPort_to_ifPort[bport.value] = connection.get("1.3.6.1.2.1.17.1.4.1.2." + str(bport.value)).value
    
    return bPort_to_ifPort

def collect_iptable(connection: snmp_conn_obj, table : dict = {}) -> dict:
    connection.use_sprint_value = True
    
    q_iptable_mac = connection.walk("1.3.6.1.2.1.4.22.1.2")
    q_iptable_ip = connection.walk("1.3.6.1.2.1.4.22.1.3")
    
    if len(q_iptable_ip) == len(q_iptable_mac):
        table_mac_iter = iter(q_iptable_mac)
        table_ip_iter = iter(q_iptable_ip)
        for mac in table_mac_iter:
            table[MAC(mac.value)] = next(table_ip_iter).value
    
    print(table)
    return table
    
def collect_devices(sw: Switch, query_hostname=True) -> Switch:
    sw.connection.use_sprint_value = True
    
    # http://oid-info.com/get/1.3.6.1.2.1.2.2.1.3
    collect_ifPorts(sw, allowed_types=("ethernetCsmacd", "fibreChannel", "ieee8023adLag"))
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
    macs_on_bridge = sw.connection.walk("1.3.6.1.2.1.17.4.3.1.1")
    for mac in macs_on_bridge:
        mac = MAC(mac.value)
        # check if valid table entry
        mac_status = int(sw.connection.get("1.3.6.1.2.1.17.4.3.1.3." + mac.as_decstr()).value)
        # skip if MAC is not learned or static configuration
        if mac_status != 3 and mac_status != 4:
            continue
        
        mac_bport = sw.connection.get("1.3.6.1.2.1.17.4.3.1.2." + mac.as_decstr()).value
        
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
    switch0 = Switch("Mellanox", [], {}, 
                     easysnmp.Session(hostname="10.161.56.25", community='public', version=2))
    switch1 = Switch("Cisco", [], {}, 
                     easysnmp.Session(hostname="10.161.56.30", community='public', version=2))
    
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
