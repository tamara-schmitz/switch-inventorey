from dataclass_defines import *
import graphviz
    
def switch_to_graph(sw : Switch, graph : graphviz.Digraph = graphviz.Digraph(name='Network Diagram'), skip_empty_ports=True) -> graphviz.Graph:
    # switches are created in their own subgraph to give them and their ports a frame
    graph.attr(layout = 'neato')
    graph.attr(compound = 'true')
    graph.attr(overlap = 'false')
    graph.attr(splines = 'spline')

    with graph.subgraph(name='cluster_' + str(sw.name)) as sub:
        sub.attr(start = 'regular')
        sub.node(sw.connection.hostname, label='Switch ' + str(sw.name), shape='box3d', pos='0,0(\'!\')?', fontsize='20')
        # fill with ports
        for port in sw.ports.values():
            if not skip_empty_ports or port.nodes:
                label = '''<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0">
                            <TR><TD COLSPAN="1">Port: {0}</TD></TR>
                            <TR><TD>Nr: {1}</TD></TR>
                        </TABLE>>'''.format(port.name, str(port.number))
                sub.node(str(port.number), label=label, shape='none', margin='0', fontsize='16')
                sub.edge(sw.connection.hostname, str(port.number), len='1', minlen='1')
            
    # add device nodes
    for port in sw.ports.values():
        if port.nodes:
            for node in port.nodes:
                label = node.mac.as_str()
                if node.vlan:
                    label += '\nVLAN: %s' % node.vlan
                if node.hostname:
                    label += '\n%s' % node.hostname
                
                graph.node(node.mac.as_str(), label=label, fontsize='14')
                graph.edge(str(port.number), node.mac.as_str(), len='2', minlen='1.75')
    
    return graph
