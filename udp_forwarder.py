#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
"""script to forward received UDP broadcast
packets to a given list of new receivers

Packets will be crafted and the previous content
will be packed into the new packet.
"""


#from scapy.all import sniff, send, IP, UDP, Ether, Raw
from scapy.all import sniff, send, IP, UDP, Ether, Raw
# import my settings
import settings as s


def showpacket(pkt, message=None):
    """shows packet via scapy's show() function
    pkt:        scapy network packet
    message:    additional header for the packet
    """
    if message:
        print 15 * "-",
        print message,
        print 15 * "-"
    pkt.show()


def send_packet(pkt):
    """send the packet
    pkt:        scapy network packet
    """
    # show the packet?
    if s.showpacks:
        showpacket(pkt, "modified")
    # send() uses layer3, so use only the IP-part of pkt
    send(pkt[IP])
    # sendp() sends layer2
    #sendp(pkt)


def craft_packet(pkt):
    """craft a new/modified packet and only transfer some information
    pkt:        scapy network packet
    returns:    newpkt: newly created scapy network packet
    """
    newpkt = Ether()/\
             IP(src=pkt[IP].src, dst=pkt[IP].dst)/\
             UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)/\
             Raw(load=pkt[Raw].load)
    return newpkt


def udp_forward(pkt):
    """if packet matches, modify it and re-send to new location
    pkt:        scapy network packet
    """
    if pkt[UDP].dport in s.ports:
        if s.showpacks:
            showpacket(pkt, "original")
        # replace packet with crafted version
        pkt = craft_packet(pkt)
        for newdest in s.newdest:
            # fill in the new destination IP
            pkt[IP].dst = newdest
            send_packet(pkt)


# main loop here
if __name__ == '__main__':
    print ">>> Sniffing on %s" % s.iface
    sniff(iface=s.iface, prn=udp_forward, filter="udp and host "+s.olddest, store=0)
