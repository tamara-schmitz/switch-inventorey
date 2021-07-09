#!/usr/bin/python3

# minimum version Python 3.7

import os
import shutil
from pathlib import Path
import textwrap
import argparse
import sys
import subprocess
import re
from dataclasses import dataclass
from concurrent import futures

try:
    subprocess.call([ "snmpget" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call([ "snmpwalk" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

except (subprocess.SubprocessError, FileNotFoundError):
    print("This program uses the snmpget and snmpwalk commands. You need to make sure that it is installed and that you can call it in a shell before running this program!")
    exit(-1)
 
def exec_cmd(cmd, capture_output=False) -> subprocess.CompletedProcess:
    if isinstance(cmd, str):
        cmd = cmd.split(' ')
        
    if not isinstance(cmd, list):
        raise TypeError("CMD must either be a list or a string")
        
    cmd.insert(0, "nice")
    cmd.insert(1, "-n19")
    return subprocess.run(cmd, shell=False, capture_output=capture_output)

@dataclass
class snmp_conn_obj:
    address: str
    version: str = "2c"
    community: str = "public"
    user: str = "admin"
    pasword: str = "admin"
    
@dataclass
class machine:
    mac: tuple
    vlan: str
    switch: str
    port: int
    port_name: str
    
    def __hash__(self):
        return hash(self.mac)
    
    def __eq__(self, other):
        return hash(self) == hash(other)
    
re_value_none = re.compile(r".*No Such Object available on this agent at this OID.*")
re_value_integer = re.compile(r".*INTEGER: (?:(\d+)|(?:.+\((\d+)\)))\s*")
re_value_hexstr = re.compile(r".*Hex-STRING:((?: ..)+)\s*")
re_value_str = re.compile(r".*STRING: (.+)\s*")

def snmp_result_extract_value(result_str: str):
    if not result_str:
        return None

    # Try for None / Null
    search_res = re_value_none.match(result_str)
    if isinstance(search_res, re.Match):
        return None
    
    # Try for Integer
    search_res = re_value_integer.match(result_str)
    if isinstance(search_res, re.Match):
        if search_res.group(1):
            return int(search_res.group(1))
        else:
            return int(search_res.group(2))
        
    # Try for Hex-String
    search_res = re_value_hexstr.match(result_str)
    if isinstance(search_res, re.Match):
        return tuple(map(lambda x: int(x, 16), search_res.groups()[0].strip().split(' ')))
    
    # Try for String
    search_res = re_value_str.match(result_str)
    if isinstance(search_res, re.Match):
        return search_res.groups()[0]
    
    raise TypeError("Unknown result type for string " + result_str)
    
def get_objid(connection: snmp_conn_obj, objid: str):
    if connection.version == "1" or connection.version == "2c":
        get_exec = exec_cmd([ "snmpget", "-O0sUX", "-v" + connection.version,
                              "-c", connection.community,
                             connection.address, objid ], True)
    
    elif connection.version == "3":
        get_exec = exec_cmd([ "snmpget", "-O0sUX", "-v" + connection.version,
                              "-l", "authNoPriv", "-a", "MD5", "-u", connection.user, "-A", connection.password,
                             connection.address, objid ], True)
    else:
        raise AttributeError("Unknown SNMP Connection Version.")
        
    return snmp_result_extract_value(get_exec.stdout.decode("utf-8"))
 
def walk_objid(connection: snmp_conn_obj, objid: str) -> dict:
    if connection.version == "1" or connection.version == "2c":
        walk_exec = exec_cmd([ "snmpwalk", "-O0sUX", "-v" + connection.version,
                              "-c", connection.community,
                             connection.address, objid ], True)
    
    elif connection.version == "3":
        walk_exec = exec_cmd([ "snmpwalk", "-O0sUX", "-v" + connection.version,
                              "-l", "authNoPriv", "-a", "MD5", "-u", connection.user, "-A", connection.password,
                             connection.address, objid ], True)
    else:
        raise AttributeError("Unknown SNMP Connection Version.")
        
    walk_lines = walk_exec.stdout.decode("utf-8").strip().split('\n')
    if '' in walk_lines:
        walk_lines.remove('')
        
    walk_dict = {}
    # split each line into key and value, add to dict
    for line in walk_lines:
        walk_k_v = line.split('=')
        walk_k_v[0] = walk_k_v[0].strip()
        walk_k_v[1] = snmp_result_extract_value(walk_k_v[1])
        walk_dict[walk_k_v[0]] = walk_k_v[1]
    
    return walk_dict
    
def collect_ifPorts(connection: snmp_conn_obj, allowed_types: tuple = (6, 56), skip_if_down: bool = True) -> dict:
    """
    OIDs
    1.3.6.1.2.1.2.2.1.1 #ifIndex
    1.3.6.1.2.1.2.2.1.2 #ifDescr
    1.3.6.1.2.1.2.2.1.3 #ifType
    1.3.6.1.2.1.2.2.1.8 #ifOperStatus (1 = up, 2 = down)
    """
    
    ifPorts = {}
    q_ifIndexes = walk_objid(connection, "ifIndex")
    
    for id in q_ifIndexes.values():
        
        # check if physical port
        ifType = get_objid(connection, "ifType." + str(id))
        # skip port if by default not an ethernet or fibre channel
        # see all types here https://www.iana.org/assignments/ianaiftype-mib/ianaiftype-mib
        if '*' not in allowed_types and ifType not in allowed_types:
            continue
        
        if skip_if_down:
            # check if link is up (optional)
            ifOperStatus = get_objid(connection, "ifOperStatus." + str(id))
            # skip port if link is down
            if ifOperStatus == 2:
                continue
        
        ifPorts[id] = get_objid(connection, "ifDescr." + str(id))
        
    return ifPorts

def collect_bPorts(connection: snmp_conn_obj) -> dict:
    """
    1.3.6.1.2.1.17.1.4.1.1 #dot1dBasePort
    1.3.6.1.2.1.17.1.4.1.2 #dot1dBasePortIfIndex
    """
    bPort_to_ifPort = {}
    q_bridge_indexes = walk_objid(connection, "1.3.6.1.2.1.17.1.4.1.1")
    for bport in q_bridge_indexes.values():
        bPort_to_ifPort[bport] = get_objid(connection, "1.3.6.1.2.1.17.1.4.1.2." + str(bport))
    
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
    macs_on_bridge = walk_objid(connection, "1.3.6.1.2.1.17.4.3.1.1")
    for mac in macs_on_bridge.values():
        
        # check if valid table entry
        mac_status = get_objid(connection, "1.3.6.1.2.1.17.4.3.1.3." + ".".join(map(str,mac)))
        # skip if MAC is not learned or static configuration
        if mac_status != 3 and mac_status != 4:
            continue
        
        # get bPort
        mac_bport = get_objid(connection, "1.3.6.1.2.1.17.4.3.1.2." + ".".join(map(str,mac)))
        
        # make device
        if mac_bport in bPort_to_ifPort and bPort_to_ifPort[mac_bport] in ifPorts:
            devices.add(machine(mac, '', connection.address,
                               bPort_to_ifPort[mac_bport], ifPorts[bPort_to_ifPort[mac_bport]]))
        
    return devices
    
    # check out vlans
    #print(walk_objid(connection, "1.3.6.1.2.1.17.7.1.4.3.1.1"))
    
def main():
    conn = snmp_conn_obj("10.161.56.25")
    conn2 = snmp_conn_obj("10.161.56.30")
    
    machines0 = collect_machines(conn)
    machines1 = collect_machines(conn2)
    
    print("Symmetric Difference: ", machines0.symmetric_difference(machines1))
    print("Intersection: ", machines0.intersection(machines1))
    
    
if __name__ == "__main__":
    sys.exit(main())
