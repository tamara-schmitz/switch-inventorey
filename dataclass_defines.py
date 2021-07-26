from dataclasses import dataclass
import easysnmp

@dataclass
class SnmpConn:
    hostname: str
    version: int = 2
    community: str = "public"
    user: str = "admin"
    password: str = "admin"
    
    def __copy__(self):
        return type(self)(self.hostname, self.version,
                          self.community, self.user, self.password)
    def copy(self):
        return self.__copy__()

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
                if not isinstance(el, int) or el >= 16 ** 2:
                    raise AttributeError("Malformed MAC given")
                l.append(el)
            self.address = tuple(l)
        
        if (isinstance(starter, str)):
            starter = starter.strip("\"., ")
            splitter = ' '
            if '-' in starter:
                splitter = '-'
            if ':' in starter:
                splitter = ':'
            l = starter.strip().split(splitter)
            
            if (len(l) == 6):
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
        return 'MAC(' + self.as_str() + ')'
    
    def __hash__(self):
        return hash(self.address)
    
    def __iter__(self):
        return iter(self.as_str())

@dataclass
class Switch:
    name: str
    macs: list
    ports: dict
    connection: SnmpConn
    vlans: tuple = ()
    
    def __hash__(self):
        return hash((self.name, self.connection.address))
    
    def __eq__(self, other):
        return hash(self) == hash(other)
    
@dataclass
class SPort:
    number: int
    name: str
    mac: MAC
    up: bool
    nodes: set
    
    def __hash__(self):
        return hash((self.number, self.parent))
    
    def __eq__(self, other):
        return hash(self) == hash(other)

@dataclass
class Node:
    mac: MAC
    hostname: str
    is_switch: Switch = None
    vlan: str = ""
    
    def __hash__(self):
        return hash(self.mac)
