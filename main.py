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
import re
import argparse
import sys
import easysnmp

from dataclass_defines import *
import snmp_get
import create_graphs

def collect_vlans(sw: Switch) -> Switch:
    vlans = []
    
    # vtpVlanEntry 1.3.6.1.4.1.9.9.46.1.3.1.1
    q_vlans = snmp_get.walk_objid(sw.connection, "1.3.6.1.4.1.9.9.46.1.3.1.1.3")
    for entry in q_vlans:
        vlan = re.match(r".*\.(\d+)$", entry.oid)
        if vlan and vlan.groups():
            vlans.append(vlan.groups()[0])
    if len(vlans) == 0:
        vlans = [None]
    sw.vlans = tuple(vlans)
    return sw

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
    for id in q_ifIndexes:
        id = id.value
        
        ifPhyAddr = snmp_get.get_objid(sw.connection, "ifPhysAddress." + str(id)).value
        ifDescr = snmp_get.get_objid(sw.connection, "ifDescr." + str(id)).value
        
        # check port type
        ifType = snmp_get.get_objid(sw.connection, "ifType." + str(id)).value
        # see all types here 
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        if ifType in filtered_types:
            continue
        
        ifOperStatus = snmp_get.get_objid(sw.connection, "ifOperStatus." + str(id)).value
        if skip_if_down:
            if 'down' in ifOperStatus:
                continue
            
        sw.ports[id] = SPort(id, ifDescr, MAC(ifPhyAddr), 'up' in ifOperStatus, set(), None)
        
    return sw

def collect_bPorts(connection: easysnmp.Session) -> dict:
    """
    1.3.6.1.2.1.17.1.4.1.1 #dot1dBasePort
    1.3.6.1.2.1.17.1.4.1.2 #dot1dBasePortIfIndex
    """
    bPort_to_ifPort = {}
    q_bridge_indexes = snmp_get.walk_objid(connection, "1.3.6.1.2.1.17.1.4.1.1")
    for bport in q_bridge_indexes:
        bPort_to_ifPort[bport.value] = snmp_get.get_objid(connection, "1.3.6.1.2.1.17.1.4.1.2." + str(bport.value)).value
    
    return bPort_to_ifPort

def collect_iptable(sw: Switch, table : dict = {}) -> dict:
    q_iptable_mac = snmp_get.walk_objid(sw.connection, "1.3.6.1.2.1.4.22.1.2")
    for item in q_iptable_mac:
        ip = re.match(r".*\.(\d+\.\d+\.\d+\.\d+)$", item.oid_index)
        if ip and ip.groups():
            table[ip.groups()[0]] = item.value
    return table
    
def collect_devices(sw: Switch, mac_to_ip_table: dict = None) -> Switch:
    
    #collect_ifPorts(sw, allowed_types=("ethernetCsmacd", "fibreChannel"))
    collect_ifPorts(sw, filtered_types=("ieee8023adLag", "softwareLoopback"))
    bPort_to_ifPort = collect_bPorts(sw.connection)
    collect_vlans(sw)
        
    # query VLAN for port
    for bport in bPort_to_ifPort:
        ifPort = bPort_to_ifPort[bport]
        if ifPort in sw.ports and not sw.ports[ifPort].vlan:
            # VLAN id 1.3.6.1.4.1.9.9.68.1.2.2.1.2
            q_ifVlanID = snmp_get.get_objid(sw.connection, "1.3.6.1.4.1.9.9.68.1.2.2.1.2." + str(ifPort))
            if not 'NOSUCH' in q_ifVlanID.snmp_type:
                sw.ports[ifPort].vlan = q_ifVlanID.value
               
    for port in sw.ports.values():
        if port.mac != MAC((0, 0, 0, 0, 0, 0)):
            sw.macs.append(port.mac)
   
    """
    # get learned macs and assosciate to phy port
    1.3.6.1.2.1.17.4.3.1.1 #dot1dTpFdbAddress
    1.3.6.1.2.1.17.4.3.1.3 #dot1dTpFdbStatus (3 = learned, 4 = self)
    1.3.6.1.2.1.17.4.3.1.2 #dot1dTpFdbPort (bridgebaseIndex)
    """
    
    for vlan in sw.vlans:
        community_suff = ''
        if vlan:
            community_suff = '@' + vlan
            
        conn = sw.connection.copy()
        conn.community = conn.community + community_suff
            
        macs_on_bridge = snmp_get.walk_objid(conn, "1.3.6.1.2.1.17.4.3.1.1")
        for mac in macs_on_bridge:
            mac = mac.value
            mac_decstr = mac.as_decstr()
            mac_bport = snmp_get.get_objid(conn, "1.3.6.1.2.1.17.4.3.1.2." + mac_decstr).value
            mac_ifport = None
            if mac_bport in bPort_to_ifPort:
                mac_ifport = bPort_to_ifPort[mac_bport]
                
            if mac_ifport not in sw.ports:
                continue
            
            mac_status = snmp_get.get_objid(conn, "1.3.6.1.2.1.17.4.3.1.3." + mac_decstr).value
            # skip if MAC is not learned or static configuration
            if mac_status != '3' and mac_status != '4':
                continue
            
            mac_hostname = ""
            if mac_to_ip_table and mac in mac_to_ip_table:
                mac_hostname = mac_to_ip_table[mac]
            
            if mac_ifport in sw.ports:
                sw.ports[mac_ifport].nodes.add(Node(mac, mac_hostname))
                
    return sw

def main():
    switch0 = Switch("Mellanox", [], {}, 
                     SnmpConn(hostname="10.161.56.25"), {})
    switch1 = Switch("Cisco", [], {}, 
                     SnmpConn(hostname="10.161.56.30"), {})
    
    print("Collecting information...")
    mac_to_ip = collect_iptable(switch0)
    mac_to_ip = collect_iptable(switch1, mac_to_ip)
    collect_devices(switch0, mac_to_ip_table = mac_to_ip)
    collect_devices(switch1, mac_to_ip_table = mac_to_ip)
    
    print("Creating graph...")
    graph = create_graphs.switch_to_graph(switch0)
    graph = create_graphs.switch_to_graph(switch1, graph)
    graph.format='pdf'
    graph.attr(dpi = '200')
    graph.render('test-graph')
    
if __name__ == "__main__":
    sys.exit(main())
