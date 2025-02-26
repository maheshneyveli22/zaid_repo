
#!/usr/bin/env python
import scapy.layers.l2 as scapy1
import scapy.sendrecv
from scapy import *

def spoof(target_ip,spoof_ip):
    packet = scapy1.ARP(op=2, pdst=target_ip , hwdst="00-0C-29-DC-63-18", psrc=spoof_ip)
    scapy1.sendp()

