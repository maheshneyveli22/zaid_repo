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
# ***
# Finished sending 256 packets
# **
# Received 5 packets, got 5 answers, remaining 251 packets
# src                manuf         psrc
# 00:67:62:a4:f8:55  FiberhomeTel  192.168.29.1
# cc:f5:5f:2b:5c:bb  EFocusInstru  192.168.29.128
# 68:c4:4d:71:aa:ac  MotorolaMobi  192.168.29.192
# bc:6e:e2:b0:34:7a  Intel         192.168.29.232
# 5c:3a:45:1c:93:73  ChongqingFug  192.168.29.41
#
# Process finished with exit code 0
