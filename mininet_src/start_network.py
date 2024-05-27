from my_topology import MyTopo

from mininet.node import RemoteController
from mininet.net import Mininet
from mininet.link import TCLink

from constatnts import controller_host
from constatnts import controller_port

def startNetwork():
    topo = MyTopo()
    controller = RemoteController('c0', ip=controller_host, port=controller_port)
    net = Mininet(topo=topo, link=TCLink, controller=controller)

    net.start()
    hosts = [net.get(f'h{i}') for i in range(1, 19)]

    return net, hosts
