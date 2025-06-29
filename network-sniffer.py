import os
import sys
try:
    from scapy.all import *
except ImportError as e:
    print("Error: Scapy library is not installed. Please install it using pip: pip install scapy")
    sys.exit()

graphviz_installed = False
try:
    import graphviz
    graphviz_installed = True
except ImportError as e:
    print("Warning: Graphviz library is not installed. No graph will be created.")

# Disclaimer and terms
print("------------------------ Packet Sniffer Tool Disclaimer ---------------------------")
print("This packet sniffer tool is intended for educational and ethical purposes only.")
print("This tool captures and analyzes only TCP packets on the network.")
print("It will capture 10 TCP packets and save the results to a file named 'packet_sniffer_results.txt'.")
print("The tool also generates a graph of the packet flow using Graphviz and saves it as 'packet_flow.png' if Graphviz is installed.")
print("By using this tool, you agree to the following terms and conditions:")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this tool without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this tool.")
print("7. You will respect the privacy and security of all networks and systems you interact with using this tool.")

print("\n--------------------- Administrative Privileges Disclaimer ------------------------")
print("This tool requires administrative or superuser privileges to capture network traffic.")
print("By running this tool with elevated privileges, you acknowledge that you understand the risks")
print("associated with running software with elevated privileges and agree to use this tool responsibly.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

if graphviz_installed:
    dot = graphviz.Digraph(comment='Packet Flow')
else:
    dot = None

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

            # Display packet information
            output_string = f"Source IP: {src_ip}\n"
            output_string += f"Destination IP: {dst_ip}\n"
            output_string += f"Protocol: {protocol}\n"
            output_string += f"Source Port: {src_port}\n"
            output_string += f"Destination Port: {dst_port}\n"
            output_string += f"Flags: {flags}\n"
            output_string += "-" * 50 + "\n"

            print(output_string, end='')
            with open('packet_sniffer_results.txt', 'a') as f:
                f.write(output_string)

            if graphviz_installed:
                dot.node(src_ip, src_ip)
                dot.node(dst_ip, dst_ip)
                dot.edge(src_ip, dst_ip, label=f"TCP {src_port} -> {dst_port}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniff TCP packets
sniff(filter="tcp", prn=packet_sniff, store=0, count=10)

if graphviz_installed:
    dot.render('packet_flow', format='png')
    print("\nResults saved to: packet_sniffer_results.txt and packet_flow.png")
else:
    print("\nResults saved to: packet_sniffer_results.txt")
