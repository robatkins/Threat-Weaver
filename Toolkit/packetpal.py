import scapy.all as scapy

#Packet Pal
#Captures packets and saves them to a .pcap file when finished.

output_file = "captured_packets.pcap"

def packet_callback(packet):
    try:
        # Save the packet to the PCAP file
        scapy.wrpcap(output_file, [packet], append=True)
        print(f"Packet captured and saved to {output_file}")
    except Exception as e:
        print(f"Error saving packet to PCAP file: {e}")

# Start sniffing
try:
    scapy.sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print("\nUser interrupted. Exiting...")

