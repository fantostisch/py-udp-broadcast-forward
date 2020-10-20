# py-udp-broadcast-forward
Small scapy script to forward UDP broadcasts to specific target IP (e.g. through a tunnel). It uses ```python-scapy``` to modify and re-send the packets.

Use cases could be to forward LAN-broadcasts from old games through a VPN-tunnel to a specific host (friend's machine) so that he sees the game in his LAN browser.

Even if there is a TCP/IP connection between both LANs, the game's broadcasts to discover "LAN games" will not reach the other subnet. 

This script sniffs the traffic on the device running the game server and resents broadcast messages on specific ports to specific IP Addresses.

# Installation

## Pre-requisites
As this script relies on scapy to perform the packet modifications we have to install it first:

FreeBSD:

`pkg install scapy`

Debian and derivatives:

`sudo apt install python3-scapy`

## Usage

Copy [example_settings/settings.example.py](example_settings/settings.example.py) to settings.py and modify to your needs.

## Run it
As scapy needs access rights to your network interfaces you need to be root to run the script:

```sh
# run the sniffer
sudo python3 udp_forwarder.py
```

## Test with scapy

If 10.0.2.255 is the intended broadcast IP address and 8888 is the corresponding UDP port then use for example scapy to send a crafted packet to see if it triggers the forwarder script:
```
root@fbsd:~ # scapy
>>> send(IP(dst="10.0.2.255")/UDP(sport=8888, dport=8888)/Raw(load="test"))
.
Sent 1 packet.
>>>
```

# Sources

- git@github.com:gqgunhed/py-udp-broadcast-forward.git
- https://github.com/gqgunhed/py-udp-broadcast-forward