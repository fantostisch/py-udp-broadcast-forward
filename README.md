# py-udp-broadcast-forward
Small scapy script to forward UDP broadcasts to specific target IP (e.g. through a tunnel). It uses python-scapy to modify and re-send the packets.

Use cases could be to forward LAN-broadcasts from old games through a VPN-tunnel to a specific host (friend's machine) so that he sees the game in his LAN browser.

Even if there is a TCP/IP connection between both LANs, the game broadcasts to discover "LAN games" will not reach the other subnet. 

So this script sniffs the traffic on the server and reacts on specific ports to re-write the destination IP-address to the given host and re-sends it.

All other fields remain unaltered.

##Pre-requisites

    pkg install scapy
