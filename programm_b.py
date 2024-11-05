import base64
import hashlib
from scapy.all import sniff, IP, ICMP, wrpcap

# Konfiguration
PCAP_FILE = 'receiver_capture.pcap'
OUTPUT_FILE = 'erhaltener_text.txt'
EXPECTED_IP = '192.168.2.164'  # IP-Adresse des Senders

# Anforderungen 1: Berechnung der Prüfsumme für die Integrität
def calculate_checksum(data):
    """Berechnet eine MD5-Prüfsumme für die Integritätsprüfung."""
    return hashlib.md5(data.encode('utf-8')).hexdigest()

# Anforderungen 2: Speichern der empfangenen Daten in einer Datei
def save_to_file(data):
    """Speichert den empfangenen und decodierten Text in einer Datei."""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as file:
        file.write(data)

# Anforderungen 3: Verarbeitung des ICMP-Verkehrs
def handle_packet(packet):
    """Verarbeitet empfangene ICMP-Pakete und stellt die Daten zusammen."""
    if IP in packet and ICMP in packet and packet[IP].src == EXPECTED_IP:
        if hasattr(packet[ICMP].payload, 'load'):
            data = packet[ICMP].payload.load.decode('utf-8')
            receive_data(data)
        
    # Speichert das Paket in der pcap-Datei
    wrpcap(PCAP_FILE, packet, append=True)

# Anforderungen 4: Empfangene Daten zusammensetzen
data_buffer = ""
def receive_data(data):
    """Empfängt und prüft die Vollständigkeit der Daten."""
    global data_buffer
    data_buffer += data

    # Überprüfen, ob wir genug Daten für die Länge und Prüfsumme haben
    if len(data_buffer) > 8:
        data_length = int(data_buffer[:8])
        if len(data_buffer) >= 8 + data_length + 32:
            encoded_data = data_buffer[8:8 + data_length]
            received_checksum = data_buffer[8 + data_length:8 + data_length + 32]

            # Prüfsumme verifizieren
            if calculate_checksum(encoded_data) == received_checksum:
                print("Datenintegrität bestätigt.")
                decoded_data = base64.b64decode(encoded_data).decode('utf-8')
                save_to_file(decoded_data)
                print("Empfangene Daten erfolgreich in 'erhaltener_text.txt' gespeichert.")
            else:
                print("Fehler: Prüfsumme stimmt nicht überein.")
            
            # Buffer zurücksetzen für weitere Nachrichten
            data_buffer = ""

# Anforderungen 5: Starten der Paketaufzeichnung und des Lauschens
def start_sniffing():
    """Startet das Sniffen der ICMP-Pakete."""
    sniff(filter="icmp", prn=handle_packet, store=0)

if __name__ == "__main__":
    print("Warte auf ICMP-Pakete...")
    start_sniffing()