from dataclass_defines import *
import graphviz
    
def switch_to_graph(sw : Switch, graph : graphviz.Digraph = graphviz.Digraph(name='Network Diagram'), skip_empty_ports=True) -> graphviz.Graph:
    # switches are created in their own subgraph to give them and their ports a frame
    graph.attr(dpi = '200')
    graph.attr(layout = 'neato')
    graph.attr(compound = 'true')
    graph.attr(overlap = 'false')
    graph.attr(splines = 'curved')

    with graph.subgraph(name='cluster_' + str(sw.name)) as sub:
        sub.attr(start = 'regular')
        sub.node(sw.connection.hostname, label='Switch ' + str(sw.name), shape='box3d', pos='0,0(\'!\')?')
        # fill with ports
        for port in sw.ports.values():
            if not skip_empty_ports or port.nodes:
                sub.node(str(port.number), label='Port ' + str(port.name), shape='box')
                sub.edge(sw.connection.hostname, str(port.number), len='2', minlen='1')
            
    # add device nodes
    for port in sw.ports.values():
        if port.nodes:
            for node in port.nodes:
                label = node.mac.as_str()
                if node.hostname:
                    label = node.hostname
                graph.node(node.mac.as_str(), label=label)
                graph.edge(str(port.number), node.mac.as_str(), len='4', minlen='2')
    
    return graph
