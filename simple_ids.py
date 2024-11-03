import pyshark
import sqlite3
import time

# Set the network interface you want to use
interface_name = 'Wi-fi'  

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('ids_log.db')
cursor = conn.cursor()

# Create a table to log alerts
cursor.execute('''
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    threat_type TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT
)
''')
conn.commit()

# Function to log alerts to the database
def log_alert(threat_type, src_ip, dest_ip, protocol):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
    INSERT INTO alerts (timestamp, threat_type, source_ip, destination_ip, protocol)
    VALUES (?, ?, ?, ?, ?)
    ''', (timestamp, threat_type, src_ip, dest_ip, protocol))
    conn.commit()

# Function to process each packet and check for potential threats
def process_packet(packet):
    try:
        if 'IP' in packet:
            source_ip = packet.ip.src
            destination_ip = packet.ip.dst
            protocol = packet.transport_layer

            # Basic threshold check for DDoS
            if protocol == 'TCP':
                # More sophisticated detection logic can be added here
                print(f"[ALERT] {time.strftime('%Y-%m-%d %H:%M:%S')} | ddos_attack | Source: {source_ip} | Destination: {destination_ip} | Protocol: {protocol}")
                log_alert('ddos_attack', source_ip, destination_ip, protocol)
    except AttributeError:
        # Occurs if the packet does not contain IP layer
        pass
    except Exception as e:
        print(f"Error processing packet: {e}")

print("Starting IDS... Press Ctrl+C to stop.")

# Start capturing packets on the specified interface
try:
    capture = pyshark.LiveCapture(interface=interface_name)

    # Process packets in real-time
    for packet in capture.sniff_continuously(packet_count=0):  # Use 0 to capture indefinitely
        process_packet(packet)

except KeyboardInterrupt:
    print("IDS stopped by user.")
finally:
    # Cleanup resources
    conn.close()
    capture.close()
    print("Database and capture resources closed.")
