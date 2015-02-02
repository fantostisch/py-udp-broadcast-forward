#!/usr/bin/env python


from scapy.all import *


PORTS = [ 8888 ]                # list of ports
OLDDEST = "10.0.2.255"          # the original broadcast address
NEWDEST = "127.0.0.10"          # the new destination of the packet
SHOWPACKS = True                # does showpacket acutally show the packets?


def showpacket(pkt, message=None):
    """shows packet via scapy's show() function"""
    if SHOWPACKS:
        if message:
            print 15 * "-",
            print message,
            print print 15 * "-"
        pkt.show()


def exchange_destination(pkt):
    """exchange the destination of the packet
    leave all other fields untouched
    """
    pkt[IP].dst = NEWDEST


def resend_packet(pkt):
    """send/relay the modified packet to its new destination"""
    sr1(pkt, timeout=1)


def udp_forward(pkt):
    """if packet matches, modify it and re-send to new location"""
    if pkt[UDP].dport in PORTS:
        showpacket(pkt, "original")
        exchange_destination(pkt)
        showpacket(pkt, "modified")
        resend_packet(pkt)


# main loop here
sniff(prn=udp_forward, filter="udp and host "+OLDDEST, store=0)

