#!/usr/bin/env python
import netfilterqueue

# Intercept packets
# a) First store it in queue using ip tables command
# -> Thus by executing below command all requests will be trapped
#
# iptables -I FORWARD -j NFQUEUE --queue-num 0
#
# b) Next step is to access this queue from python program
# -> To do this, first we need to install netfilterqueue module
#
# c) Write python program to access the queue and modify the packets
###############################
# This  program helps to modify packets
###############################

#call back function
def process_packet(packet):
    print(packet)
    # Option1: accept method will forward the packet to its destination, thus internet will be allowed
    packet.accept()
    # Option2 : drop the packet or cut the internet of the target client
    #packet.drop()




#Creating an object to interact with Queue 0
queue = netfilterqueue.NetfilterQueue()
# To connect or bind the queue to the queue which we created via IP tables
# 0 indicates queue number
# is call back function which is executed on each packet of the queue
queue.bind(0, process_packet)
# Run the queue by calling queue.run()
queue.run()


# This program can be used to cut internet connection for any client in the network