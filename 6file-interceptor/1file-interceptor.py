#In file interceptor - we will modify data in the http layer
#We will intercept - When user tries to download a file and replace it with another file which could be harmful
# File Could be a) backdoor b) Credential Harvester c) Virus
# We will use a combination of ARP spoofing program and File Interceptor to achieve this


# Goal of this program is to write a program that can detect when a user requests to download a certain file
# Upon detecting that file request, we will serve a different file
# TO achieve the same we will take the DNS spoof code which we wrote last section and remove certain lines


#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy

#1
# In this program first we will check if packet has http layer
# if a packet contains http layer with useful data, it will contain in the raw layer
# Thus how scapy works is : it has main layers which are IP, TCP, UDP and
# finally at the end, it appends the raw data such as http data in the raw layer
# to check if a packet contains this layer, all we have to do is just type raw instead of DNS

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # 1
    # In this program first we will check if packet has http layer
    # if a packet contains http layer with useful data, it will contain in the raw layer
    # Thus how scapy works is : it has main layers which are IP, TCP, UDP and
    # finally at the end, it appends the raw data such as http data in the raw layer
    # to check if a packet contains this layer, all we have to do is just type raw instead of DNS

#2 Now we dont know, which packets are requests and which packets are responses
    if scapy_packet.haslayer(scapy.Raw):
        print(scapy_packet.show())




    packet.accept()



queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
