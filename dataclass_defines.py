from dataclasses import dataclass

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
