# IMPORTANT:
# Must be run as super-user to use low-level packet interfaces


import sys
import logging

from scapy.config import conf
from scapy.sendrecv import sniff

from scapy.layers.l2 import Ether,ARP
from scapy.layers.inet import ICMP,IP,UDP,TCP


# logging.basicConfig(level=logging.WARN)
# logging.getLogger("scapy").setLevel(logging.WARN)
# logging.getLogger("sniffer").setLevel(logging.INFO)
conf.verb = 0   # Verbosity level 0..2


def udp_sniff(interface, svr_addr, svr_port):
    pkts = sniff(iface=interface, count=0, filter=f"udp and host {svr_addr} and port {svr_port}", prn = lambda x: x.summary())


if __name__ == "__main__":
    udp_sniff('lo', '10.38.35.182', 1234)
