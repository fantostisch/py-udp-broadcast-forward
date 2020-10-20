#!/usr/bin/env python3
"""example settings
"""

# list of ports to listen react upon
ports = [ 8888 ]

# broadcast address that triggers the forwarding
olddest = "10.0.2.255"

# list of new destination ranges for the modified packet
newdestranges = [ "10.0.2.0/24" ]

# show the original and modified packet?
# Only enable for debugging, slows down program
showpacks = False

# listen on which network interface?
iface = "em0"
