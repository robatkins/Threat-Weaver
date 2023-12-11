import socket

#PACKETSNIPER
#Custom Packet Sending Toolkit

def send_udp_packet(ip_address, port, message, num_packets):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for _ in range(num_packets):
        udp_socket.sendto(message.encode(), (ip_address, port))

    udp_socket.close()

def send_tcp_packet(ip_address, port, message):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.connect((ip_address, port))
    tcp_socket.send(message.encode())
    tcp_socket.close()

if __name__ == "__main__":
    print("Packet Sniper ~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    # Get user input for target IP address and port
    target_ip = input("Enter the target IP address: ")
    target_port = int(input("Enter the target port: "))

    # Get user input for the message and number of packets to send
    message_to_send = input("Enter the message to send: ")
    num_packets_to_send = int(input("Enter the number of packets to send: "))

    # Ask the user which packet to send
    protocol_choice = input("Enter 'udp' or 'tcp' to choose the protocol: ").lower()

    if protocol_choice == 'udp':
        send_udp_packet(target_ip, target_port, message_to_send, num_packets_to_send)
    elif protocol_choice == 'tcp':
        send_tcp_packet(target_ip, target_port, message_to_send)
    else:
        print("Invalid protocol choice. Please enter 'udp' or 'tcp'.")
