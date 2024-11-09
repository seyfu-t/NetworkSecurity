import base64
import hashlib
from scapy.all import ICMP, IP, sr1, send, sniff

# Konfiguration
FILENAME = 'text_to_send.txt'
TARGET_IP = 'localhost'  # IP-Adresse des Empfängers
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

# Anforderungen 5: Speichern der empfangenen Daten in einer Datei
def save_to_file(data):
    """Speichert den empfangenen und decodierten Text in einer Datei."""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

if __name__ == "__main__":
    send_data_icmp()
