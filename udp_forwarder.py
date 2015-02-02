#!/usr/bin/env python


from scapy.all import *


PORTS = [ 53, 8888 ]            # list of ports
OLDDEST = "10.0.2.255"          # the original broadcast address
NEWDEST = "127.0.0.10"          # the new destination of the packet


def exchange_destination(pkt):
    """exchange the destination of the packet
    leave all other fields untouched
    """
    pkt[IP].dst = NEWDEST
    pkt.show()                  # shows the modified packet


def resend_packet(pkt):
    """send/relay the modified packet to its new destination"""
    sr1(pkt, timeout=1)


def udp_forward(pkt):
    """if packet matches, modify it and re-send to new location"""
    if UDP in pkt and pkt[IP].dst==OLDDEST and pkt[UDP].dport in PORTS:
        #pkt.show()              # shows the original/unaltered packet
        exchange_destination(pkt)
        resend_packet(pkt)


# main loop here
sniff(prn=udp_forward, filter="udp", store=0)

