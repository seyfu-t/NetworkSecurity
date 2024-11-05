import socket
import base64
import hashlib
from scapy.all import ICMP, IP, sr1, send, sniff
import threading

# Konfiguration
FILENAME = 'text_to_send.txt'
TARGET_IP = '192.168.2.171'  # IP-Adresse des Empfängers
PCAP_FILE = 'receiver_capture.pcap'
OUTPUT_FILE = 'erhaltener_text.txt'

# Anforderungen 1: Auslesen und Codieren der Datei
def read_and_encode_file(filename):
    """Liest die Datei ein und codiert den Inhalt in Base64."""
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read()
    encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')
    return encoded_data

# Anforderungen 2: Berechnung der Prüfsumme für die Integrität
def calculate_checksum(data):
    """Berechnet eine MD5-Prüfsumme für die Integritätsprüfung."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# Anforderungen 3: Senden der Daten über ICMP
def send_data_icmp():
    """Liest und sendet codierte Daten mit Prüfsumme über ICMP."""
    encoded_data = read_and_encode_file(FILENAME)
    checksum = calculate_checksum(encoded_data)
    data_to_send = f"{len(encoded_data):08d}{encoded_data}{checksum}"
    
    # Sende die Daten in ICMP-Paketen
    for i in range(0, len(data_to_send), 48):  # Teile die Nachricht in kleinere Teile
        chunk = data_to_send[i:i+48]
        packet = IP(dst=TARGET_IP)/ICMP(type=8)/chunk
        response = sr1(packet, timeout=1, verbose=0)
        if response is None:
            print(f"Fehler: Keine Antwort für das Paket mit Daten: {chunk}")
        else:
            print(f"Gesendet: {chunk}")

# Anforderungen 4: Empfangen der Daten über ICMP
def receive_data_icmp():
    """Empfängt codierte Daten mit Prüfsumme über ICMP, überprüft und speichert die Daten."""
    def packet_callback(packet):
        if ICMP in packet and packet[ICMP].type == 8 and packet[IP].src == TARGET_IP:
            received_chunk = packet[ICMP].load.decode('utf-8')
            received_data.append(received_chunk)
            print(f"Empfangen: {received_chunk}")

    received_data = []
    print("Warte auf ICMP-Daten...")
    sniff(filter="icmp", prn=packet_callback, timeout=10, stop_filter=lambda x: len(received_data) > 0)

    # Zusammensetzen der empfangenen Daten
    full_data = ''.join(received_data)
    data_length = int(full_data[:8])
    encoded_data = full_data[8:8+data_length]
    received_checksum = full_data[8+data_length:]

    # Prüfen der Integrität und Decodieren der Daten
    if calculate_checksum(encoded_data) == received_checksum:
        print("Datenintegrität bestätigt.")
        decoded_data = base64.b64decode(encoded_data).decode('utf-8')
        save_to_file(decoded_data)
        print("Empfangene Daten erfolgreich in 'erhaltener_text.txt' gespeichert.")
    else:
        print("Fehler: Prüfsumme stimmt nicht überein.")

# Anforderungen 5: Speichern der empfangenen Daten in einer Datei
def save_to_file(data):
    """Speichert den empfangenen und decodierten Text in einer Datei."""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

if __name__ == "__main__":
    # Wähle entweder das Senden oder das Empfangen
    action = input("Möchten Sie Daten senden oder empfangen? (s/e): ").strip().lower()
    if action == 's':
        send_data_icmp()
    elif action == 'e':
        receive_data_icmp()
    else:
        print("Ungültige Eingabe. Bitte 's' für senden oder 'e' für empfangen eingeben.")
