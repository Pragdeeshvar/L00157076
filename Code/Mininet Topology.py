

CPU_PORT = 255

from mininet.cli import CLI
from mininet.log import log
from mininet.net import Mininet
from mininet.topo import Topo
from stratum import StratumBmv2Switch





class mytopo(Topo):
    

    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        
        # Leaf switch 1 and 2
        
        leafswitch1 = self.addSwitch('s1', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        leafswitch2 = self.addSwitch('s2', cls=StratumBmv2Switch, cpuport=CPU_PORT)

        # Spine switch 1 and two
        
        spineswitch1 = self.addSwitch('s3', cls=StratumBmv2Switch, cpuport=CPU_PORT)
        spineswitch2 = self.addSwitch('s4', cls=StratumBmv2Switch, cpuport=CPU_PORT)

         host1 = self.addHost('h1', mac="00:00:00:00:00:01",
                           ipv6='2001:1:1::1/64', ipv6_gw='2001:1:1::ff')
        host2 = self.addHost('h2', mac="00:00:00:00:00:20",
                          ipv6='2001:1:1::2/64', ipv6_gw='2001:1:1::ff')
        self.addLink(host1, leafswitch1)  
        self.addLink(host2, leafswitch1)  

        
        h3 = self.addHost('h3', mac="00:00:00:00:00:30",
                          ipv6='2001:1:2::1/64', ipv6_gw='2001:2:1::ff')
        h4 = self.addHost('h4', mac="00:00:00:00:00:40",
                          ipv6='2001:1:2::2/64', ipv6_gw='2001:2:2::ff')
        self.addLink(host3, leafswitch2)  
        self.addLink(host4, leafswitch2) 

        # Switch Links
        self.addLink(spineswitch1, leafswitch1)
        self.addLink(spineswitch1, leafswitch2)
        self.addLink(spineswitch2, leafswitch1)
        self.addLink(spineswitch2, leafswitch2)

        # IPv6 hosts attached to leaf 1
        


def main():
    net = Mininet(topo=minitopo(), controller=None)
    net.start()
    CLI(net)
    net.stop()



