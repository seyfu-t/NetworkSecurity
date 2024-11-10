import base64
import hashlib
from scapy.all import sniff, IP, ICMP, send

# Configuration
OUTPUT_FILE = 'erhaltener_text.txt'
EXPECTED_IP = '192.168.2.164'  # Sender's IP address
received_packets = {}
total_packets = None  # Total number of packets expected
missing_packets_queue = []  # Queue for missing or invalid packets

# Simulate checksum error for testing
skip = True
stop_received = False  # Flag to indicate when the STOP message has been received

# Handle incoming ICMP packets and assemble data
def handle_packet(packet):
    global received_packets, total_packets, skip, missing_packets_queue, stop_received
    if IP in packet and ICMP in packet and packet[IP].src == EXPECTED_IP:
        if hasattr(packet[ICMP].payload, 'load'):
            try:
                data = packet[ICMP].payload.load.decode('utf-8')

                # Skip processing for control messages
                if data.startswith("RESEND:"):
                    return

                if data.startswith("START:"):
                    total_packets = int(data.split(":")[1])
                    print(f"START message received. Expecting {total_packets} packets.\n\n\n")
                    return

                if data == "STOP":
                    print(f"\n\n\nSTOP message received.")
                    stop_received = True  # Set flag when STOP is received
                    handle_missing_packets_queue()
                    return

                # Handle regular packet
                packet_num = int(data[:4])
                chunk = data[4:-32]
                received_checksum = data[-32:]

                # # Simulate checksum error for packet 6
                # if skip and packet_num == 6:
                #     received_checksum = received_checksum[:2] + 'b' + received_checksum[3:]
                #     skip = False

                # Verify checksum and store valid packets
                if calculate_checksum(chunk) == received_checksum:
                    decoded_chunk = base64.b64decode(chunk).decode('utf-8')
                    print(f"{decoded_chunk}", end='')
                    received_packets[packet_num] = chunk
                else:
                    print(f"Checksum error in packet {packet_num}. Adding to queue for retransmission.")
                    if packet_num not in missing_packets_queue:
                        missing_packets_queue.append(packet_num)

            except ValueError as e:
                print(f"Error parsing packet payload: {e}")

# Request retransmission of packets in the queue
def handle_missing_packets_queue():
    global missing_packets_queue, stop_received
    if len(received_packets) == total_packets:
        print("All packets received, no need for retransmission.")
        save_data_to_file()
        stop_received = False  # Reset the flag after saving data
        return
    # Request retransmission for packets in the queue
    for packet_num in missing_packets_queue:
        if packet_num not in received_packets:
            print(f"Requesting retransmission for missing packet {packet_num}.")
            request_resend(packet_num)

    # Keep listening for new incoming packets after requesting retransmissions
    if stop_received:
        sniff(filter="icmp", prn=handle_packet, timeout=5, store=0)
        if len(received_packets) == total_packets:
            print("All packets received after retransmissions. Saving data.")
            save_data_to_file()
        else:
            print(f"Still missing packets after retransmissions. Expected {total_packets}, but only received {len(received_packets)}.")
    missing_packets_queue.clear()

# Save the received and decoded data to a file
def save_data_to_file():
    ordered_data = ''.join([received_packets[i] for i in sorted(received_packets)])
    decoded_data = base64.b64decode(ordered_data).decode('utf-8')
    save_to_file(decoded_data)
    print("Data saved successfully to 'erhaltener_text.txt'.")

# Request retransmission of a specific packet
def request_resend(packet_num):
    resend_packet = IP(dst=EXPECTED_IP)/ICMP(type=8)/f"RESEND:{packet_num:04d}"
    send(resend_packet, verbose=0)
    print(f"Retransmission request sent for packet {packet_num}.")

# Save the received and decoded data to a file
def save_to_file(data):
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

# Calculate checksum for integrity verification
def calculate_checksum(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

if __name__ == "__main__":
    print("Waiting for ICMP packets...")
    sniff(filter="icmp", prn=handle_packet, store=0)
