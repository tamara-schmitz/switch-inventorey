import easysnmp
from dataclass_defines import *

def result_extract_value(in_value):
        try: 
            return MAC(in_value)
        except AttributeError:
            return in_value
        
def create_easysnmp_sess(conn_obj: SnmpConn) -> easysnmp.Session:
    return easysnmp.Session(hostname=conn_obj.hostname,
                            community=conn_obj.community,
                            version=conn_obj.version,
                            security_username=conn_obj.user,
                            auth_password=conn_obj.password)
    
def get_objid(connection, objid: str):
    conn = connection
    if isinstance(connection, SnmpConn):
        conn = create_easysnmp_sess(connection)
    if not isinstance(conn, easysnmp.Session):
        raise ArgumentError("Expecting an easysnmp.Session or SnmpConn")
        
    conn.use_sprint_value = True
    
    item = conn.get(objid)
    item.value = result_extract_value(item.value)
    return item
 
def walk_objid(connection, objid: str) -> dict:
    conn = connection
    if isinstance(connection, SnmpConn):
        conn = create_easysnmp_sess(connection)
    if not isinstance(conn, easysnmp.Session):
        raise ArgumentError("Expecting an easysnmp.Session or SnmpConn")
        
    conn.use_sprint_value = True
       
    res = conn.walk(objid)
    
    for item in res:
        item.value = result_extract_value(item.value)
    
    return res
    
