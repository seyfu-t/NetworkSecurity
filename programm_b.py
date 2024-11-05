import socket
import base64
import hashlib
from scapy.all import sniff, wrpcap

# Konfiguration
HOST = '0.0.0.0'  # Lauschen auf allen Interfaces
PORT = 65432
PCAP_FILE = 'receiver_capture.pcap'
OUTPUT_FILE = 'erhaltener_text.txt'

# Anforderungen 1: Berechnung der Prüfsumme für die Integrität
def calculate_checksum(data):
    """Berechnet eine MD5-Prüfsumme für die Integritätsprüfung."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# Anforderungen 2: Packet Capture
def packet_capture(filter_rule, pcap_file):
    """Startet die Paketaufzeichnung nach einer bestimmten Filterregel."""
    packets = sniff(filter=filter_rule, count=10)  # Anpassbar für die gewünschte Anzahl
    wrpcap(pcap_file, packets)

# Anforderungen 3: Empfangen der Daten
def receive_data():
    """Empfängt codierte Daten mit Prüfsumme über TCP, überprüft und speichert die Daten."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print("Warte auf Verbindung...")

        conn, addr = s.accept()
        with conn:
            print(f"Verbunden mit {addr}. Empfange Daten...")

            # Starte die Paketaufzeichnung parallel
            packet_capture("tcp", PCAP_FILE)

            data_length = int(conn.recv(8).decode('utf-8'))
            data = conn.recv(data_length).decode('utf-8')
            received_checksum = conn.recv(32).decode('utf-8')
            
            if calculate_checksum(data) == received_checksum:
                print("Datenintegrität bestätigt.")
                decoded_data = base64.b64decode(data).decode('utf-8')
                save_to_file(decoded_data)
                print("Empfangene Daten erfolgreich in 'erhaltener_text.txt' gespeichert.")
            else:
                print("Fehler: Prüfsumme stimmt nicht überein.")

# Anforderungen 4: Speichern der empfangenen Daten in einer Datei
def save_to_file(data):
    """Speichert den empfangenen und decodierten Text in einer Datei."""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

if __name__ == "__main__":
    receive_data()
