import base64
import hashlib
from scapy.all import ICMP, IP, sr1, send, sniff

# Configuration
FILENAME = 'text_to_send.txt'
TARGET_IP = '192.168.2.171'  # Receiver's IP address
OUTPUT_FILE = 'erhaltener_text.txt'

# Read and encode the file
def read_and_encode_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read()
    encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    return encoded_data

# Calculate checksum for integrity verification
def calculate_checksum(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# Send data via ICMP with per-packet checksum
def send_data_icmp():
    encoded_data = read_and_encode_file(FILENAME)
    packet_size = 48
    total_packets = len(encoded_data) // packet_size + (1 if len(encoded_data) % packet_size else 0)

    for i in range(total_packets):
        chunk = encoded_data[i * packet_size:(i + 1) * packet_size]
        checksum = calculate_checksum(chunk)
        packet = IP(dst=TARGET_IP)/ICMP(type=8)/(f"{i:04d}" + chunk + checksum)
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            print(f"Warning: No response for packet {i}")
        else:
            print(f"Sent packet {i}")

# Listen for retransmission requests and resend packets
def handle_resend_request(packet):
    if IP in packet and ICMP in packet and hasattr(packet[ICMP].payload, 'load'):
        request = packet[ICMP].payload.load.decode('utf-8')
        if request.startswith("RESEND:"):
            packet_num = int(request.split(":")[1])
            print(f"Resending packet {packet_num}")
            encoded_data = read_and_encode_file(FILENAME)
            packet_size = 48
            chunk = encoded_data[packet_num * packet_size:(packet_num + 1) * packet_size]
            checksum = calculate_checksum(chunk)
            resend_packet = IP(dst=TARGET_IP)/ICMP(type=8)/(f"{packet_num:04d}" + chunk + checksum)
            send(resend_packet, verbose=0)

# Start listening for retransmission requests
def listen_for_requests():
    sniff(filter="icmp", prn=handle_resend_request, store=0)

if __name__ == "__main__":
    send_data_icmp()
    print("Listening for retransmission requests...")
    listen_for_requests()
