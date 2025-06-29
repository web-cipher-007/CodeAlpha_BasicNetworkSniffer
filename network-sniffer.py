import os
import sys
try:
    from scapy.all import *
    import graphviz
except ImportError as e:
    if "graphviz" in str(e):
        print("Error: Graphviz library is not installed. Please install it using pip: pip install graphviz")
    elif "scapy" in str(e):
        print("Error: Scapy library is not installed. Please install it using pip: pip install scapy")
    else:
        print(f"Error: {e}")
    sys.exit()

# Disclaimer and terms
print("------------------------ Packet Sniffer Tool Disclaimer ---------------------------")
print("This packet sniffer tool is intended for educational and ethical purposes only.")
print("This tool captures and analyzes only TCP packets on the network.")
print("It will capture 10 TCP packets and save the results to a file named 'packet_sniffer_results.txt'.")
print("The tool also generates a graph of the packet flow using Graphviz and saves it as 'packet_flow.png'.")
print("By using this tool, you agree to the following terms and conditions:")
print("\n1. You will only use this tool on networks and systems for which you have explicit permission.")
print("2. You will not use this tool to violate any laws, regulations, or terms of service.")
print("3. You will not use this tool to harm, disrupt, or exploit any networks or systems.")
print("4. You will not use this tool to intercept, collect, or store any sensitive or confidential information.")
print("5. You will not redistribute or sell this tool without the express permission of the author.")
print("6. The author is not responsible for any damages or losses incurred as a result of using this tool.")
print("7. You will respect the privacy and security of all networks and systems you interact with using this tool.")
print("\nNote: This tool requires Graphviz to be installed on your system to display the packet flow graph as a PNG image.")

accept_terms = input("\nDo you accept these terms and conditions? (y/n): ")

if accept_terms.lower() != 'y':
    print("You must accept the terms and conditions before using this tool.")
    sys.exit()

try:
    dot = graphviz.Digraph(comment='Packet Flow')
    dot.render('test', format='png')
    os.remove('test.png')
except Exception as e:
    print("Error: Graphviz system package is not installed or not configured correctly. Please install it from the official Graphviz website.")
    print(f"Error details: {e}")
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

            # Add packet to graph
            dot.node(src_ip, src_ip)
            dot.node(dst_ip, dst_ip)
            dot.edge(src_ip, dst_ip, label=f"TCP {src_port} -> {dst_port}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Create graph
dot = graphviz.Digraph(comment='Packet Flow')

# Sniff TCP packets
sniff(filter="tcp", prn=packet_sniff, store=0, count=10)

# Save graph
dot.render('packet_flow', format='png')

print("\nResults saved in: packet_sniffer_results.txt and packet_flow.png")
