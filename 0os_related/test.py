from scapy.all import *

# Example: Load a pcap file (replace with your file)
packets = rdpcap("your_capture.pcap")

for packet in packets:
    if TCP in packet and packet[TCP].dport == 80: #or packet[TCP].dport == 443
        if Raw in packet[TCP]:
            try:
                http_packet = HTTP(packet[TCP].payload)
                http_packet.show()
            except:
                print ("Could not dissect HTTP")