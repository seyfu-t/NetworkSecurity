import base64
import hashlib
from scapy.all import sniff, IP, ICMP, send

# Configuration
OUTPUT_FILE = 'erhaltener_text.txt'
EXPECTED_IP = '192.168.2.164'  # Sender's IP address
received_packets = {}
total_packets = None  # Total number of packets expected

# Handle incoming ICMP packets and assemble data
def handle_packet(packet):
    global received_packets, total_packets
    if IP in packet and ICMP in packet and packet[IP].src == EXPECTED_IP:
        if hasattr(packet[ICMP].payload, 'load'):
            try:
                data = packet[ICMP].payload.load.decode('utf-8')

                # Handle START message
                if data.startswith("START:"):
                    total_packets = int(data.split(":")[1])
                    print(f"START message received. Expecting {total_packets} packets.")
                    return

                # Handle STOP message
                if data == "STOP":
                    print("STOP message received.")
                    if len(received_packets) == total_packets:
                        print("All packets received. Saving data.")
                        ordered_data = ''.join([received_packets[i] for i in sorted(received_packets)])
                        decoded_data = base64.b64decode(ordered_data).decode('utf-8')
                        save_to_file(decoded_data)
                        print("Data saved successfully to 'erhaltener_text.txt'.")
                        return
                    else:
                        print(f"Missing packets. Expected {total_packets}, but only received {len(received_packets)}.")#
                        # TODO: request missing
                        return

                # Handle regular packet
                packet_num = int(data[:4])
                chunk = data[4:-32]
                received_checksum = data[-32:]

                # Verify checksum
                if calculate_checksum(chunk) == received_checksum:
                    print(f"Packet {packet_num} integrity confirmed.")
                    received_packets[packet_num] = chunk

                # Request retransmission for any missing packets up to the current number
                for num in range(len(received_packets)):
                    if num not in received_packets:
                        print(f"Packet {num} missing. Requesting retransmission.")
                        request_resend(num)

            except ValueError as e:
                print(f"Error parsing packet payload: {e}")





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
