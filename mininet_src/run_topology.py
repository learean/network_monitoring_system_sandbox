from mininet.log import setLogLevel
from mininet.cli import CLI
from start_network import startNetwork

def main():
    setLogLevel('info')

    net, hosts = startNetwork()

    print(hosts)

    # Drop into CLI for exploring the topology
    CLI(net)

    net.stop()


if __name__ == '__main__':
    main()
