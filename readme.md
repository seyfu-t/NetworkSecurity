# Netzwerk Security Projekt

Dieses Projekt umfasst zwei Programme zur Simulation der Datenübertragung auf Netzwerkebene, die zur Analyse von Netzwerkprotokollen beitragen. Die Programme wurden erfolgreich lokal auf einem Linux-Host in separaten Terminals getestet.

## Voraussetzungen

- Linux-Host
- Separate Terminals für Sender- und Empfängerprogramm

## Installation

1. **Bibliotheken installieren**: Stelle sicher, dass alle erforderlichen Bibliotheken für Python vorhanden sind. Falls fehlend, installiere sie individuell nach Bedarf.

## Ausführung

1. **Programme mit Root-Rechten ausführen**: Beide Programme erfordern `sudo`-Berechtigungen.
   
2. **Reihenfolge beachten**:
   - **Empfängerprogramm (Programm_b) zuerst starten**: Dies setzt das System in Empfangsbereitschaft.
   - **Senderprogramm (Programm_a) starten**: Das Programm initiiert die Übertragung der Daten.

3. **Dateierstellung und automatische Beendigung**: Beide Programme erzeugen die benötigten Dateien und beenden sich automatisch nach erfolgreicher Übertragung.

## To-Do-Liste

1. **Code überprüfen**: Sicherstellen, dass der Code den Anforderungen entspricht und mögliche Anpassungen vornehmen.
2. **Anforderungen überprüfen**: Bestätigen, dass alle Vorgaben korrekt umgesetzt wurden.
3. **Protokoll anpassen**: Derzeit basiert der Code auf TCP; diesen durch ICMP ersetzen, wie in den Projektspezifikationen gefordert.
