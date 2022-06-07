# IMPORTANT:
# Must be run as super-user to use low-level packet interfaces


import sys
import logging
import time
from parser import parse_scenario

from scapy.config import conf
from scapy.compat import raw
from scapy.sendrecv import srp,sr,send,sniff,sendp
from scapy.packet import Raw
from scapy.layers.l2 import Ether,ARP
from scapy.layers.inet import ICMP,IP,UDP,TCP

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger("trafficgen")
logger.setLevel(logging.INFO)
conf.verb = 0   # Verbosity level 0..2
count=0

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


def udp_flow(flowspec,count):
    # logger.debug(flow['quantity'])
    # logger.debug(flow['interval'])
    # logger.debug(flow['size'])
    # logger.debug(flow['dest'])
    mode = flowspec['quantity']['mode']
    

    if flow['size']['mode']=='const':
        payload_size = flow['size']['packet_size'] - IP_HEADER-UDP_HEADER
        # payload = b'0'*payload_size
        # JM (ERROR EN ' FINAL)
        # payload = f'{x:010d}{'0'*(payload_size-11)}'
        # JO
        payload = str('0').zfill(payload_size)
    else:
        logger.error("Size mode {flow['size']['mode']} not implemented")
        return

    if mode=='packet':
        packet = Ether(dst=flow['dest']['mac'])/IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'],sport=count)/Raw(load=payload)
        packet = IP(raw(packet))    # Compute len and checksum fields
        # logger.debug(packet.show(dump=True))
        if flow['interval']['mode']=='greedy':
            #logger.info(f"{packet.summary()}, greedy qty={flow['quantity']['packets']}")
            # sendp(packet, count=flow['quantity']['packets'], verbose=False, iface="eth0")
            # JM
            # packet_list = [IP(raw(IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'])/Raw(load=f'{i:010d}{"0"*(payload_size-11)}'))) for i in range (flow['quantity']['packets'])]
            # JO
            packet_list = [IP(raw(Ether(dst=flow['dest']['mac'])/IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'],sport=count)/Raw(load='{:010d}{:01462d}'.format(i,0)))) for i in range (flow['quantity']['packets'])]
            logger.info("{packet.summary()}, greedy qty="+str(len(packet_list)))
            sendp(packet_list,verbose=False)
        elif flow['interval']['mode']=='const':
            logger.info("{packet.summary()}, const qty={flow['quantity']['packets']} inter={flow['interval']['time']}")
            sendp(packet, count=flow['quantity']['packets'], inter=flow['interval']['time'], verbose=False)
        else:
            logger.error("interval mode {flow['interval']['mode']} not implemented")
    elif mode=='time':
        t_end=time.time()+flow['quantity']['secs']
        logger.info("Time for {flow['quantity']['secs']} seconds")
        logger.info("Time: {time.time()}")
        packet = IP(dst=flow['dest']['addr'])/UDP(dport=flow['dest']['port'],sport=count)/Raw(load=payload)
        packet = IP(raw(packet))    # Compute len and checksum fields
        while time.time()<t_end:
            if flow['interval']['mode']=='greedy':
                logger.info("{packet.summary()}, greedy qty={flow['quantity']['packets']}")
                send(packet, count=flow['quantity']['packets'], verbose=False)
            elif flow['interval']['mode']=='const':
                logger.info("{packet.summary()}, const qty={flow['quantity']['packets']} inter={flow['interval']['time']}")
                send(packet, count=flow['quantity']['packets'], inter=flow['interval']['time'], verbose=False)
            else:
                logger.error("interval mode {flow['interval']['mode']} not implemented")

        logger.info("Time: {time.time()}")
    else:
        logger.error('quantity={mode} not supported')


MTU = 1500
IP_HEADER = 20
UDP_HEADER = 8
PAYLOAD_SIZE = MTU-IP_HEADER-UDP_HEADER


if __name__ == "__main__":
    scenario = parse_scenario(sys.argv[1])
    if scenario['type']=='tcp':
        logger.error('TCP not implemented')
        exit(-1)
    count=0
    for i in range(scenario['repeat']):
        # logger.debug('Iteration: {i}')
        for flow in scenario['flows']:
            if flow['on']:
                count+=1
                udp_flow(flow,count)
            else:
                t1=time.time()
                time.sleep(flow['offtime'])
                t2=time.time()
                # logger.info('Slept for {t2-t1} secs')

    # arp_ping('10.38.35.1')
    # icmp_ping('10.38.35.1')
    # udp_flow('10.38.35.182', 1234, 10)

