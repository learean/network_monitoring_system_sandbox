
from mininet.log import setLogLevel
from time import sleep
from random import choice

from start_network import startNetwork
from utils import ip_generator



def generate_normal_traffic(net, hosts):
    h1 = net.get('h1')
    h1.cmd('cd /home/mininet/webserver')
    h1.cmd('python -m SimpleHTTPServer 80 &')
    h1.cmd('iperf -s -p 5050 &')
    h1.cmd('iperf -s -u -p 5051 &')
    sleep(2)

    for host in hosts:
        host.cmd('cd /home/mininet/Downloads')

    for i in range(100):
        print(f"Iteration {i + 1} ...")

        for j in range(10):
            src = choice(hosts)
            dst = ip_generator()

            src.cmd(f"ping {dst} -c 100 &")
            src.cmd("iperf -p 5050 -c 10.0.0.1")
            src.cmd("iperf -p 5051 -u -c 10.0.0.1")
            src.cmd("wget http://10.0.0.1/index.html")
            src.cmd("wget http://10.0.0.1/test.zip")

        h1.cmd("rm -f *.* /home/mininet/Downloads")


def main():
    setLogLevel('info')

    net, hosts = startNetwork()

    generate_normal_traffic(net, hosts)

    net.stop()


if __name__ == '__main__':
    main()
