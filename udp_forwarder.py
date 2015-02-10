#!/usr/bin/env python


from scapy.all import *
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


def exchange_destination(pkt, newdest):
    """exchange the destination of the packet
    leave all other fields untouched
    pkt:        scapy network packet
    newdest:    string of single new IP address
    """
    pkt[IP].dst = newdest

def send_packet(pkt):
    """send modified packet"""
    pkt = Ether()/IP(dst=pkt[IP].dst)/UDP(sport=pkt[UDP].sport,dport=pkt[UDP].dport)/Raw(load=pkt[Raw].load)
    # show the packet?
    if s.showpacks:
        showpacket(pkt, "modified")
    # send() uses layer3
    send(pkt[IP])
    # sendp() sends layer2
    #sendp(pkt)


def udp_forward(pkt):
    """if packet matches, modify it and re-send to new location
    pkt:        scapy network packet
    """
    if pkt[UDP].dport in s.ports:
        if s.showpacks:
            showpacket(pkt, "original")
        for newdest in s.newdest:
            exchange_destination(pkt, newdest)
            send_packet(pkt)


# main loop here
if __name__ == '__main__':
    print ">>> Sniffing on %s" % s.iface
    sniff(iface=s.iface, prn=udp_forward, filter="udp and host "+s.olddest, store=0)
