# IMPORTANT:
# Must be run as super-user to use low-level packet interfaces


import sys
import logging
import time
from parser import parse_scenario

from scapy.config import conf
from scapy.compat import raw
from scapy.sendrecv import srp,sr,send,sniff
from scapy.packet import Raw
from scapy.layers.l2 import Ether,ARP
from scapy.layers.inet import ICMP,IP,UDP,TCP

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger("trafficgen")
logger.setLevel(logging.INFO)
conf.verb = 1   # Verbosity level 0..2


def arp_ping(pdst):
    '''Do an ARP resolution'''
    ans,unans=srp(Ether(dst=b"ff:ff:ff:ff:ff:ff")/ARP(pdst=pdst),timeout=2)
    ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )


def icmp_ping(ip_dst):
    '''Ping destination host'''
    ans, unans = sr(IP(dst=ip_dst)/ICMP())
    ans.summary(lambda s,r: r.sprintf("%IP.src% is alive") )


def udp_packets(dst_host, dst_port, n_packets, interval):
    '''Transmit an UDP flow of n_packets to a dst_host:dst_port'''
    packet = IP(dst=dst_host)/UDP(dport=dst_port)/Raw(load=payload)
    packet = IP(raw(packet))    # Compute len and checksum fields
    logger.debug(packet.summary())
    logger.debug(packet.show(dump=True))
    send(packet, count=n_packets, inter=interval)


def udp_flow(flowspec):
    logger.debug(flow['quantity'])
    logger.debug(flow['interval'])
    logger.debug(flow['size'])
    logger.debug(flow['dest'])
    mode = flowspec['quantity']['mode']

    if flow['size']['mode']=='const':
        payload_size = flow['size']['packet_size'] - IP_HEADER-UDP_HEADER
        payload = b'0'*payload_size
    else:
        logger.error(f"Size mode {flow['size']['mode']} not implemented")
        return

    if mode=='packet':
        packet = IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'])/Raw(load=payload)
        packet = IP(raw(packet))    # Compute len and checksum fields
        # logger.debug(packet.show(dump=True))
        if flow['interval']['mode']=='greedy':
            logger.info(f"{packet.summary()}, greedy qty={flow['quantity']['packets']}")
            send(packet, count=flow['quantity']['packets'], verbose=False)
        elif flow['interval']['mode']=='const':
            logger.info(f"{packet.summary()}, const qty={flow['quantity']['packets']} inter={flow['interval']['time']}")
            send(packet, count=flow['quantity']['packets'], inter=flow['interval']['time'], verbose=False)
        else:
            logger.error(f"interval mode {flow['interval']['mode']} not implemented")
    elif mode=='time':
        t_end=time.time()+flow['quantity']['secs']
        logger.info(f"Time for {flow['quantity']['secs']} seconds")
        logger.info(f"Time: {time.time()}")
        packet = IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'])/Raw(load=payload)
        packet = IP(raw(packet))    # Compute len and checksum fields
        while time.time()<t_end:
            if flow['interval']['mode']=='greedy':
                logger.info(f"{packet.summary()}, greedy qty={flow['quantity']['packets']}")
                send(packet, count=flow['quantity']['packets'], verbose=False)
            elif flow['interval']['mode']=='const':
                logger.info(f"{packet.summary()}, const qty={flow['quantity']['packets']} inter={flow['interval']['time']}")
                send(packet, count=flow['quantity']['packets'], inter=flow['interval']['time'], verbose=False)
            else:
                logger.error(f"interval mode {flow['interval']['mode']} not implemented")

        logger.info(f"Time: {time.time()}")
    else:
        logger.error(f'quantity={mode} not supported')


MTU = 1500
IP_HEADER = 20
UDP_HEADER = 8
PAYLOAD_SIZE = MTU-IP_HEADER-UDP_HEADER


if __name__ == "__main__":
    scenario = parse_scenario(sys.argv[1])
    if scenario['type']=='tcp':
        logger.error('TCP not implemented')
        exit(-1)
    for i in range(scenario['repeat']):
        logger.debug(f'Iteration: {i}')
        for flow in scenario['flows']:
            if flow['on']:
                udp_flow(flow)
            else:
                t1=time.time()
                time.sleep(flow['offtime'])
                t2=time.time()
                logger.info(f'Slept for {t2-t1} secs')

    # arp_ping('10.38.35.1')
    # icmp_ping('10.38.35.1')
    # udp_flow('10.38.35.182', 1234, 10)