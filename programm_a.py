import base64
import hashlib
from scapy.all import ICMP, IP, sr1, send, sniff

# Configuration
FILENAME = 'text_to_send.txt'
TARGET_IP = '192.168.2.171'  # Receiver's IP address
MAX_ATTEMPTS = 5

# Store chunks for possible retransmissions
sent_chunks = {}

# Send data via ICMP with per-packet checksum
def send_data_icmp():
    global sent_chunks
    encoded_data = read_and_encode_file(FILENAME)
    packet_size = 48  # Total packet size, including the checksum
    checksum_length = 32  # Length of the MD5 checksum
    data_chunk_size = packet_size - checksum_length  # Adjusted size for the actual data

    total_packets = len(encoded_data) // data_chunk_size + (1 if len(encoded_data) % data_chunk_size else 0)

    # Send the START message
    if not send_packet_with_retries(IP(dst=TARGET_IP)/ICMP(type=8)/f"START:{total_packets:04d}", "START"):
        print("Sending 'START' failed. Exiting...")
        exit(1)

    for i in range(total_packets):
        chunk = encoded_data[i * data_chunk_size:(i + 1) * data_chunk_size]
        checksum = calculate_checksum(chunk)
        packet_data = f"{i:04d}" + chunk + checksum
        packet = IP(dst=TARGET_IP)/ICMP(type=8)/packet_data
        sent_chunks[i] = packet  # Store packet for potential retransmission

        if not send_packet_with_retries(packet, f"Packet {i}"):
            print(f"Failed to receive acknowledgment for packet {i} after {MAX_ATTEMPTS} attempts.")
            exit(1)

    # Send the STOP message
    if not send_packet_with_retries(IP(dst=TARGET_IP)/ICMP(type=8)/"STOP", "STOP"):
        print("Sending 'STOP' failed. Exiting...")
        exit(1)

# Send a packet with retry logic
def send_packet_with_retries(packet, packet_name):
    attempts = 0
    success = False

    while attempts < MAX_ATTEMPTS:
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            attempts += 1
            print(f"Attempt {attempts}: No response for {packet_name}, retrying...")
        else:
            print(f"{packet_name} sent successfully.")
            success = True
            break

    if not success:
        print(f"Failed to receive acknowledgment for {packet_name} after {MAX_ATTEMPTS} attempts.")

    return success

# Read and encode the file
def read_and_encode_file(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read()
    encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    return encoded_data

# Calculate checksum for integrity verification
def calculate_checksum(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

if __name__ == "__main__":
    send_data_icmp()
    print("Transmission completed. Listening for potential retransmission requests...")
    
    # This should listen for incoming retransmission requests from the receiver.
    def handle_incoming_request(packet):
        if IP in packet and ICMP in packet and hasattr(packet[ICMP].payload, 'load'):
            data = packet[ICMP].payload.load.decode('utf-8')
            if data.startswith("RESEND:"):
                packet_num = int(data.split(":")[1])
                if packet_num in sent_chunks:
                    print(f"Resending packet {packet_num} due to request.")
                    send(sent_chunks[packet_num], verbose=0)

    sniff(filter="icmp", prn=handle_incoming_request, store=0)
