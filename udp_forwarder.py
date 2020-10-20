#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
"""script to forward received UDP broadcast
packets to a given list of new receivers

Packets will be crafted and the previous content
will be packed into the new packet.
"""


from scapy.all import *
from scapy.layers.inet import IP, UDP, Ether
import ipaddress

# import my settings
import settings as s


def showpacket(pkt, message=None):
    """shows packet via scapy's show() function
    pkt:        scapy network packet
    message:    additional header for the packet
    """
    # show the packet?
    if s.showpacks:
        if message:
            print(15 * "-" + message + 15 * "-")
        pkt.show()


def craft_packet(pkt):
    """craft a new/modified packet and only transfer some information
    pkt:        scapy network packet
    returns:    newpkt: newly created scapy network packet
    """
    newpkt = Ether()/\
             IP(dst=pkt[IP].dst)/\
             UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport)/\
             Raw(load=pkt[Raw].load)
    return newpkt


def udp_forward(pkt):
    """if packet matches, modify it and re-send to new location
    pkt:        scapy network packet
    """
    if pkt[UDP].dport in s.ports:
        before = datetime.now()
        showpacket(pkt, "original")
        # replace packet with crafted version
        pkt = craft_packet(pkt)
        packet_list = []
        for new_dest_range in s.newdestranges:
            for ip in ipaddress.ip_network(new_dest_range):
                new_pkt = pkt.copy()
                # fill in the new destination IP
                new_pkt[IP].dst = str(ip)
                showpacket(new_pkt, "modified")
                packet_list.append(new_pkt)

        packet_list_l3 = []
        for p in packet_list:
            packet_list_l3.append(p[IP])

        after = datetime.now()
        diff = after - before
        print("Creating packets took: " + str(diff.total_seconds()) + " seconds.")

        # send() uses layer3, so use only the IP-part of pkt
        send(packet_list_l3)
        # sendp() sends layer2
        # sendp(packet_list)


# main loop here
if __name__ == '__main__':
    print(">>> Sniffing on %s" % s.iface)
    sniff(iface=s.iface, prn=udp_forward, filter="udp and host "+s.olddest, store=0)
