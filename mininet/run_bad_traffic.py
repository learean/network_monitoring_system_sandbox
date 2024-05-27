from mininet.log import setLogLevel
from time import sleep
from random import choice

from start_network import startNetwork
from utils import ip_generator

def generate_ddos_traffic(hosts):
    attack_cmds = [
        "timeout 20s hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood {dst}",
        "timeout 20s hping3 -2 -V -d 120 -w 64 --rand-source --flood {dst}",
        "timeout 20s hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1",
        "timeout 20s hping3 -1 -V -d 120 -w 64 --flood -a {dst} {dst}"
    ]

    for cmd in attack_cmds:
        src = choice(hosts)
        dst = ip_generator()
        print(f"Executing attack: {cmd.format(dst=dst)}")
        src.cmd(cmd.format(dst=dst))
        sleep(100)


def main():
    setLogLevel('info')

    net, hosts = startNetwork()

    generate_ddos_traffic(hosts)

    net.stop()


if __name__ == '__main__':
    main()
