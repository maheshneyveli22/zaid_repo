from scapy.all import sniff, IP, TCP
import re

def packet_callback(packet):
    """
    Prints the HTTP payload for all HTTP requests (GET, POST, etc.)
    """
    if IP in packet and TCP in packet:
        if packet[TCP].dport == 80 or packet[TCP].dport == 8080:  # Check for HTTP ports
            payload = packet[TCP].payload
            try:
                http_payload = bytes(payload).decode("utf-8", errors="ignore")  # Decode payload, ignore errors

                # Check for HTTP request methods (GET, POST, PUT, DELETE, etc.)
                if re.search(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+.*HTTP/", http_payload, re.MULTILINE):
                    print("--- HTTP Request Payload ---")
                    print(http_payload)
                    print("--- End HTTP Request Payload ---")

                    #Optional: Extract specific headers or data using regular expressions
                    #Example: Extract Host header:
                    host_match = re.search(r"Host: (.*?)\r\n", http_payload)
                    if host_match:
                        print(f"Host: {host_match.group(1)}")
                    #Example: Extract User-Agent header:
                    user_agent_match = re.search(r"User-Agent: (.*?)\r\n", http_payload)
                    if user_agent_match:
                        print(f"User-Agent: {user_agent_match.group(1)}")
                    #Example: Extract the requested path
                    path_match = re.search(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+(.*?)\s+HTTP/", http_payload)
                    if path_match:
                        print(f"Path: {path_match.group(2)}")

            except UnicodeDecodeError:
                # Handle cases where the payload is not valid UTF-8
                print("--- Non-UTF-8 HTTP Payload (possibly binary) ---")
                print(payload) #Print raw bytes instead.
                print("--- End Non-UTF-8 HTTP Payload ---")

try:
    sniff(filter="tcp port 80 or tcp port 8080", prn=packet_callback, store=0)

except PermissionError:
    print("You need root privileges to run sniff(). Try running with sudo.")
except KeyboardInterrupt:
    print("\nSniffing stopped.")