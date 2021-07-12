import subprocess
import re
from concurrent import futures
from dataclass_defines import *

# Check for installed SNMP tools
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
    
re_value_none = re.compile(r".*No Such.*", flags=re.IGNORECASE)
re_value_integer = re.compile(r".*INTEGER: (?:(\d+)|(?:.+\((\d+)\)))\s*", flags=re.IGNORECASE)
re_value_hexstr = re.compile(r".*Hex-STRING:((?: ..)+)\s*", flags=re.IGNORECASE)
re_value_str = re.compile(r".*(?:(?:STRING)|(?:IpAddress)): (.+)\s*", flags=re.IGNORECASE)

def snmp_result_extract_value(result_str: str):
    # TODO Improve detection of empty strings
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
        try: 
            return MAC(search_res.groups()[0])
        except AttributeError:
            pass
    
    # Try for String
    search_res = re_value_str.match(result_str)
    if isinstance(search_res, re.Match):
        try: 
            return MAC(search_res.groups()[0])
        except AttributeError:
            return search_res.groups()[0]
    
    print("Warning! Unknown SNMP result type for string " + result_str)
    return None
    
def get_objid(connection: snmp_conn_obj, objid: str):
    cmd = [ "snmpget", "-O0sUX" ]
    if connection.version == "1" or connection.version == "2c":
        cmd.extend([ "-v" + connection.version, "-c", connection.community,
                     connection.address, objid ])
    
    elif connection.version == "3":
        cmd.extend([ "-v" + connection.version,
                    "-l", "authNoPriv", "-a", "MD5",
                    "-u", connection.user, "-A", connection.password,
                    connection.address, objid ])
    else:
        raise AttributeError("Unknown SNMP Connection Version.")
        
    return snmp_result_extract_value(exec_cmd(cmd, True).stdout.decode("utf-8"))
 
def walk_objid(connection: snmp_conn_obj, objid: str) -> dict:
    cmd = [ "snmpwalk", "-O0sUX" ]
    if connection.version == "1" or connection.version == "2c":
        cmd.extend([ "-v" + connection.version, "-c", connection.community,
                    connection.address, objid ])
    
    elif connection.version == "3":
        cmd.extend([ "-v" + connection.version,
                    "-l", "authNoPriv", "-a", "MD5",
                    "-u", connection.user, "-A", connection.password,
                    connection.address, objid ])
    else:
        raise AttributeError("Unknown SNMP Connection Version.")
        
    walk_lines = exec_cmd(cmd, True).stdout.decode("utf-8").strip().split('\n')
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
    
