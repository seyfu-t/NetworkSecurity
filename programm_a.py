import socket
import base64
import hashlib
from scapy.all import sniff, wrpcap
import threading

# Konfiguration
FILENAME = 'text_to_send.txt'
HOST = 'localhost'  # IP-Adresse des Empfängers
PORT = 65432
PCAP_FILE = 'sender_capture.pcap'

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

# Anforderungen 3: Packet Capture
def packet_capture(filter_rule, pcap_file):
    """Startet die Paketaufzeichnung nach einer bestimmten Filterregel."""
    packets = sniff(filter=filter_rule, count=10)  # Anpassbar für die gewünschte Anzahl
    wrpcap(pcap_file, packets)

# Anforderungen 4: Senden der Daten über TCP
def send_data():
    """Liest und sendet codierte Daten mit Prüfsumme über TCP."""
    encoded_data = read_and_encode_file(FILENAME)
    checksum = calculate_checksum(encoded_data)
    data_to_send = f"{len(encoded_data):08d}{encoded_data}{checksum}"

    # Starte die Paketaufzeichnung in einem separaten Thread
    capture_thread = threading.Thread(target=packet_capture, args=("tcp", PCAP_FILE))
    capture_thread.start()

    # Erstelle die TCP-Verbindung und sende die Daten
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Verbunden mit dem Empfänger. Sende Daten...")
        s.sendall(data_to_send.encode('utf-8'))
        print("Daten und Prüfsumme gesendet.")

    # Warte, bis die Paketaufzeichnung abgeschlossen ist
    capture_thread.join()

if __name__ == "__main__":
    send_data()
