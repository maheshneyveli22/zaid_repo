#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http 


def sniff(interface):#
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)





def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())


# find interfaces in windows using power shell; by using command - netsh interface show interface
#
#
# PS C:\Users\gs1-maheswarane> netsh interface show interface
#
# Admin State    State          Type             Interface Name
# -------------------------------------------------------------------------
# Enabled        Disconnected   Dedicated        Ethernet
# Enabled        Connected      Dedicated        Ethernet 4
# Enabled        Disconnected   Dedicated        Wi-Fi


sniff("Ethernet 4")
#sniff("Wi-Fi")