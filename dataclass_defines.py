from dataclasses import dataclass

@dataclass
class MAC:
    address: tuple = None
    
    def __init__(self, starter):
        if not starter:
            self.address = (0, 0, 0, 0, 0, 0)
        
        if (isinstance(starter, MAC)):
            self.address = starter.address
            
        if (isinstance(starter, (tuple, list)) and
            len(starter) == 6):
            l = []
            for el in starter:
                if isinstance(el, str) and len(el) <= 2:
                    el = int(el, 16)
                if not isinstance(el, int):
                    raise AttributeError("Malformed MAC given")
                l.append(el)
            self.address = tuple(l)
        
        if (isinstance(starter, str)):
            starter = starter.strip()
            splitter = ' '
            if '-' in starter:
                splitter = '-'
            if ':' in starter:
                splitter = ':'
            l = starter.strip().split(splitter)
            
            if (len(l) == 6 and 
                all(len(el) == 2 for el in l)):
                self.address = tuple(int(el, 16) for el in l)
            
        if not self.address:
            raise AttributeError("Malformed MAC of type given")
        
    def as_tuple(self):
        return self.address
    
    def as_str(self):
        return "-".join(map(lambda x : '{:0>2X}'.format(x), self.address))
    
    def as_decstr(self):
        return ".".join(map(str,self.address))
    
    def __repr__(self):
        return self.as_str()
    
    def __hash__(self):
        return hash(self.address)

@dataclass
class snmp_conn_obj:
    address: str
    version: str = "2c"
    community: str = "public"
    user: str = "admin"
    pasword: str = "admin"
    
@dataclass
class machine:
    mac: MAC
    vlan: str
    switch: str
    port: int
    port_name: str
    
    def __hash__(self):
        return hash(self.mac, self.switch, self.port)
    
    def __eq__(self, other):
        return hash(self) == hash(other)

@dataclass
class Switch:
    name: str
    macs: list
    ports: dict
    connection: snmp_conn_obj
    
    def __hash__(self):
        return hash((self.name, self.ips, self.macs))
    
    def __eq__(self, other):
        return hash(self) == hash(other)
    
@dataclass
class SPort:
    number: int
    name: str
    #parent: Switch
    mac: MAC
    up: bool
    nodes: set
    vlan: str = ""
    
    def __hash__(self):
        return hash((self.number, self.parent))
    
    def __eq__(self, other):
        return hash(self) == hash(other)

@dataclass
class Node:
    mac: MAC
    vlan: str = ""
    is_switch: Switch = None
    
    def __hash__(self):
        return hash(self.mac)
