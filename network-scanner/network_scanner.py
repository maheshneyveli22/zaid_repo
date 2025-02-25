#!/usr/bin/env python
import scapy.layers.l2
from scapy.layers.l2 import *

def scan(ip):
    scapy.layers.l2.arping(ip)

scan("192.168.29.1/24")
#scan("192.168.177.2/24")

# o/p:
# C:\Users\Maheswaran\AppData\Local\Programs\Python\Python311\python.exe E:\zaid_mahe\python_zaid_projects\network-scanner\network_scanner.py
# Begin emission
#
# Finished sending 1 packets
# *
# Received 1 packets, got 1 answers, remaining 0 packets
# src                manuf         psrc
# 00:67:62:a4:f8:55  FiberhomeTel  192.168.29.1
#
# Process finished with exit code 0
