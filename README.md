#py-udp-broadcast-forward
Small scapy script to forward UDP broadcasts to specific target IP (e.g. through a tunnel). It uses python-scapy to modify and re-send the packets.

##Caution: Work-in-progress

Use cases could be to forward LAN-broadcasts from old games through a VPN-tunnel to a specific host (friend's machine) so that he sees the game in his LAN browser.

Even if there is a TCP/IP connection between both LANs, the game's broadcasts to discover "LAN games" will not reach the other subnet. 

So this script sniffs the traffic on the server and reacts on specific ports to re-write the destination IP-address to the given host and re-sends it.

All other fields remain unaltered.

#Installation

##Pre-requisites
As this script relies on scapy to perform the packet modifications we have to install it first:
FreeBSD:

    pkg install scapy

Ubuntu:

    sudo apt-get install python-scapy
    
##Get the script

    git clone https://github.com/gqgunhed/py-udp-broadcast-forward
    cd py-udp-broadcast-forward

modify settings.py to reflect your actual environment
    
    cp settings.py.sample settings.py
    vi settings.py


##Run it
As scapy needs access rights to your network interfaces you need to be root to run the script:
    
    # run the sniffer
    sudo python udp_forwarder.py

##Test with scapy

If 10.0.2.255 is the intended broadcast IP address and 8888 is the corresponding UDP port then use for example scapy to send a crafted packet to see if it triggers the forwarder script:

    root@fbsd:~ # scapy
    >>> send(IP(dst="10.0.2.255")/UDP(sport=8888, dport=8888)/Raw(load="test"))
    .
    Sent 1 packet.
    >>>

