import os
import sys
from scapy.all import *

# Disclaimer and terms
print("------------------------ Packet Sniffer Tool Disclaimer ---------------------------")
print("This packet sniffer tool is intended for educational and ethical purposes only.")
print("Unauthorized use, distribution, or modification of this tool is strictly prohibited.")
print("By using this tool, you agree to the following terms and conditions:")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this tool without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this tool.")
print("7. You will respect the privacy and security of all networks and systems you interact with using this tool.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

print("\n--------------- Packet Sniffing Tool ---------------")

# Function to analyze and display captured packets
def packet_sniff(packet):
    try:
        # Extract IP information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Determine protocol
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            payload = str(packet[TCP].payload)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = ""
            payload = str(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = ""
            dst_port = ""
            flags = packet[ICMP].type
            payload = str(packet[ICMP].payload)
        else:
            protocol = "Unknown"
            src_port = ""
            dst_port = ""
            flags = ""
            payload = ""

        # Display packet information
        output_string = f"Source IP: {src_ip}\n"
        output_string += f"Destination IP: {dst_ip}\n"
        output_string += f"Protocol: {protocol}\n"
        output_string += f"Source Port: {src_port}\n"
        output_string += f"Destination Port: {dst_port}\n"
        output_string += f"Flags: {flags}\n"
        output_string += f"Payload: {payload[:50]}...\n"
        output_string += "-" * 50 + "\n"

        print(output_string, end='')
        with open('packet_sniffer_results.txt', 'a') as f:
            f.write(output_string)

    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniff packets
sniff(prn=packet_sniff, store=0, count=10)

print("\nResults saved to: packet_sniffer_results.txt")
