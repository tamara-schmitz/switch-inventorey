import easysnmp
from dataclass_defines import *

def snmp_result_extract_value(in_value):
        try: 
            return MAC(in_value)
        except AttributeError:
            return in_value
    
def get_objid(sess: easysnmp.Session, objid: str):
    item = sess.get(objid)
    return (snmp_result_extract_value()
 
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
    
