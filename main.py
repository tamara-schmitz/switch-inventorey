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



def check_for_snmp_utils():
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
    mac: str
    vlan: str
    switch: str
    port: str
    
def snmp_result_extract_value(result_str: str):
    # Try for Integer
    search_res = re.match(".*INTEGER: \D*\(?(\d+)\)?\D*", result_str)
    if isinstance(search_res, re.Match):
        return int(search_res.groups()[0])
    
    # Try for String
    search_res = re.match(".*STRING: (.+)$", result_str)
    if isinstance(search_res, re.Match):
        return search_res.groups()[0]
    
    raise TypeError("Unknown result type for string " + result_str)
    
def get_objid(connection: snmp_conn_obj, objid: str) -> str:
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
        
    return get_exec.stdout.decode("utf-8").strip()
 
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
        
    # split each line into key and value
    walk_dict = dict(map(lambda line: map(str.strip, line.split('=')),
                        walk_lines))
    
    return walk_dict
    
def collect_ifPorts(connection: snmp_conn_obj) -> dict:
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
        id = str(snmp_result_extract_value(id))
        
        # check if physical port
        ifType = snmp_result_extract_value(get_objid(connection, "ifType." + id))
        # skip port if not an ethernet or fibre channel
        if ifType != 6 and ifType != 56:
            continue
        
        # check if link is up
        ifOperStatus = snmp_result_extract_value(get_objid(connection, "ifOperStatus." + id))
        # skip port if link is down
        if ifOperStatus == 2:
            continue
        
        ifPorts[id] = snmp_result_extract_value(get_objid(connection, "ifDescr." + id))
        
    return ifPorts
       
def collect_machines(connection: snmp_conn_obj) -> list:
    # http://oid-info.com/get/1.3.6.1.2.1.2.2.1.3
    # check port names ifname
    ifPorts = collect_ifPorts(connection)
    print(ifPorts)
    
    """
    # get learned macs and assosciate to phy port
    1.3.6.1.2.1.17.4.3.1.1 #dot1dTpFdbAddress
    1.3.6.1.2.1.17.4.3.1.3 #dot1dTpFdbStatus (3 = learned)
    1.3.6.1.2.1.17.4.3.1.2 #dot1dTpFdbPort (bridgebaseIndex)
    # resolve dot1dTpFdbPort to ifIndex
    1.3.6.1.2.1.17.1.4.1.2(.bridgebaseIndex)
    1.3.6.1.2.1.17.1.4.1.1 # all bridgebaseIndexes
    
    """
    
    # check out vlans
    #print(walk_objid(connection, "1.3.6.1.2.1.17.7.1.4.3.1.1"))
    
def main():
    conn = snmp_conn_obj("10.161.56.25")
    #print(walk_objid(conn, ".1.3.6.1.2.1.17.7.1.2.2"))
    #print(walk_objid(conn, ".1.3.6.1.2.1.17.7.1.1"))
    #print(walk_objid(conn, ".1.3.6.1.2.1.1.1"))
    #print(walk_objid(conn, ".1.3.6.1.2.1.1.3"))
    #print(walk_objid(conn, ".1.3.6.1.2.1.17.7.1.1"))
    #print(walk_objid(conn, "1.3.6.1.2.1.17.7.1.4.3.1.1"))
    #print(walk_objid(conn, "1.3.6.1.2.1.31.1.1.1.18"))
    #print(walk_objid(conn, "1.0.8802.1.1.2.1.4.1.1.9"))
    
    collect_machines(conn)
    
if __name__ == "__main__":
    check_for_snmp_utils()
    sys.exit(main())
