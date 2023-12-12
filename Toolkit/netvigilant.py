from scapy.all import ARP, Ether, srp

#NETVIGILANT
#Reconnaisance tool to determine which devices are on the local network

def scan_local_devices(ip_range="192.168.1.1/24"):
    # Create ARP request packet
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)

    # Send the packet and receive the response
    result = srp(arp_request, timeout=3, verbose=0)[0]

    # Extract the list of devices
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def main():
    # You can specify the IP range based on your network configuration
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")

    # Scan the local devices
    devices = scan_local_devices(ip_range)

    # Display the results
    print("\nList of devices on the network:")
    print("IP Address\t\tMAC Address")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    main()
