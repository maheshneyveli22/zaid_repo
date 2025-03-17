from scapy.all import sniff
from scapy.layers.http import HTTPRequest  # Import HTTPRequest layer


def process_packet(packet):
    # Check if the packet has an HTTPRequest layer
    if packet.haslayer(HTTPRequest):
        print(packet.show())
        # Extract and print the requested URL
        # url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # print(f"[+] HTTP Request >> {url}")
        #
        # # Print additional fields from the HTTP request
        # fields = packet[HTTPRequest].fields
        # print(f"Fields: {fields}")


# Sniff packets on a specific interface (e.g., "eth0") and process them
print("Sniffing packets...")
sniff(iface="Wi-Fi", store=False, prn=process_packet)
