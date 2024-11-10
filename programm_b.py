import base64
import hashlib
from scapy.all import sniff, IP, ICMP, send

# Configuration
OUTPUT_FILE = 'erhaltener_text.txt'
EXPECTED_IP = '192.168.2.164'  # Sender's IP address
MAX_ATTEMPTS = 5



# Handle incoming ICMP packets and assemble data
received_packets = {}
expected_packet_num = 0  # Tracks the expected next packet number

def handle_packet(packet):
    global expected_packet_num
    if IP in packet and ICMP in packet and packet[IP].src == EXPECTED_IP:
        if hasattr(packet[ICMP].payload, 'load'):
            try:
                data = packet[ICMP].payload.load.decode('utf-8')
                if data.startswith("RESEND:"):
                    # Skip processing as this is a request from the receiver, not incoming data
                    return

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

                # Detect and request missing packets
                while expected_packet_num < packet_num:
                    print(f"Packet {expected_packet_num} missing. Requesting retransmission.")
                    request_resend(expected_packet_num)
                    expected_packet_num += 1

                # Update expected packet number after successful reception
                expected_packet_num = packet_num + 1

                # Check if all data has been received and save if complete
                if received_packets:
                    ordered_data = ''.join([received_packets[i] for i in sorted(received_packets)])
                    if len(ordered_data) >= sum(len(chunk) for chunk in received_packets.values()):
                        decoded_data = base64.b64decode(ordered_data).decode('utf-8')
                        save_to_file(decoded_data)
                        print("Data saved successfully to 'erhaltener_text.txt'.")

            except ValueError as e:
                print(f"Error parsing packet payload: {e}")

# Request retransmission of a specific packet
def request_resend(packet_num):
    resend_packet = IP(dst=EXPECTED_IP)/ICMP(type=8)/f"RESEND:{packet_num:04d}"
    send(resend_packet, verbose=0)





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
