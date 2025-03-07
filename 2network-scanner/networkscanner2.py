#!/usr/bin/env python
import scapy.layers.l2
from scapy.layers.l2 import *


#goal : Discover clients on network

#Steps:
#1. Create ARP request directed to broadcast MAC asking for IP
#two main parts:
# -> Use ARP to ask who has target IP
# -> set destination mac to broadcast mac
#2. Send packet and receive response
#3. Parse the response
#4. Print result



def scan(ip):
    # -> Use ARP to ask who has target IP
    arp_request = scapy.layers.l2.ARP(pdst=ip)
    # -> set destination mac to broadcast mac
    #Create Ethernet object
    broadcast = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # 2. Send packet and receive response
    answered_list, unanswered_list =scapy.layers.l2.srp(arp_request_broadcast, timeout=1, verbose=False)
   # print(answered_list)
    print("IP\t\t\t\t\t\tMAC Address list\n------------------------------------------------------------------------------")
    for element in answered_list:
     print(element[1].psrc +"\t\t"+element[1].hwsrc)


#4. Print result


# C:\Users\Maheswaran\AppData\Local\Programs\Python\Python311\python.exe E:\zaid_mahe\python_zaid_projects\network-scanner\networkscanner2.py
# Begin emission
# ..*........................................*.......................................................................................*........................................................*..................................................................**.......
# Finished sending 256 packets
# ...
# Received 267 packets, got 6 answers, remaining 250 packets
# Ether / ARP who has 192.168.29.1 says 192.168.29.41 ==> Ether / ARP is at 00:67:62:a4:f8:55 says 192.168.29.1
# Ether / ARP who has 192.168.29.41 says 192.168.29.41 ==> Ether / ARP is at 5c:3a:45:1c:93:73 says 192.168.29.41
# Ether / ARP who has 192.168.29.128 says 192.168.29.41 ==> Ether / ARP is at cc:f5:5f:2b:5c:bb says 192.168.29.128 / Padding
# Ether / ARP who has 192.168.29.168 says 192.168.29.41 ==> Ether / ARP is at 0e:ed:e1:c0:50:a0 says 192.168.29.168
# Ether / ARP who has 192.168.29.192 says 192.168.29.41 ==> Ether / ARP is at 68:c4:4d:71:aa:ac says 192.168.29.192
# Ether / ARP who has 192.168.29.232 says 192.168.29.41 ==> Ether / ARP is at bc:6e:e2:b0:34:7a says 192.168.29.232
# None

#3. Parse the response


scan("192.168.29.1/24")
