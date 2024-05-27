from mininet.topo import Topo
from mininet.node import OVSKernelSwitch

class MyTopo(Topo):
    def build(self):
        switches = []
        hosts = []

        for i in range(1, 7):
            switch = self.addSwitch(f's{i}', cls=OVSKernelSwitch, protocols='OpenFlow13')
            switches.append(switch)

            for j in range(1, 4):
                host_num = (i - 1) * 3 + j
                host = self.addHost(f'h{host_num}', cpu=1.0/20, mac=f"00:00:00:00:00:{host_num:02}", ip=f"10.0.0.{host_num}/24")
                hosts.append(host)
                self.addLink(host, switch)

        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i + 1])

        return hosts

topos = {'mytopo': (lambda: MyTopo())}
