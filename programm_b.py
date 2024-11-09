import base64
import hashlib
from scapy.all import sniff, IP, ICMP, send

# Configuration
OUTPUT_FILE = 'erhaltener_text.txt'
EXPECTED_IP = '127.0.0.1'  # Sender's IP address

# Calculate checksum for integrity verification
def calculate_checksum(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# Save the received and decoded data to a file
def save_to_file(data):
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

# Handle incoming ICMP packets and assemble data
received_packets = {}
def handle_packet(packet):
    if IP in packet and ICMP in packet and packet[IP].src == EXPECTED_IP:
        if hasattr(packet[ICMP].payload, 'load'):
            data = packet[ICMP].payload.load.decode('utf-8')
            packet_num = int(data[:4])
            chunk = data[4:-32]
            received_checksum = data[-32:]

            # Verify checksum
            if calculate_checksum(chunk) == received_checksum:
                print(f"Packet {packet_num} integrity confirmed.")
                received_packets[packet_num] = chunk
            else:
                print(f"Checksum error in packet {packet_num}. Requesting retransmission.")
                request_resend(packet_num)

            # Check if all data has been received
            if received_packets:
                total_data = ''.join([received_packets[i] for i in sorted(received_packets)])
                decoded_data = base64.b64decode(total_data).decode('utf-8')
                save_to_file(decoded_data)
                print("Data saved successfully to 'erhaltener_text.txt'.")

# Request retransmission of a specific packet
def request_resend(packet_num):
    resend_packet = IP(dst=EXPECTED_IP)/ICMP(type=8)/f"RESEND:{packet_num:04d}"
    send(resend_packet, verbose=0)

# Start sniffing for ICMP packets
def start_sniffing():
    sniff(filter="icmp", prn=handle_packet, store=0)

if __name__ == "__main__":
    print("Waiting for ICMP packets...")
    start_sniffing()
