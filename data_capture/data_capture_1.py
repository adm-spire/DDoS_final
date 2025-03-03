import pyshark
import pandas as pd
import numpy as np
import pickle
import time
from river.tree import HoeffdingAdaptiveTreeClassifier
from collections import defaultdict
from scapy.all import send, IP, TCP, RandShort
import threading

# Configuration
INTERFACE = "Wi-Fi 2"
CAPTURE_DURATION = 60  # Capture traffic for 60 seconds
OUTPUT_CSV = "captured_traffic_with_labels.csv"
MODEL_FILE = "hat_model.pkl"

# Feature list
FEATURES = ['Average Packet Size', 'Fwd Packet Length Min', 'Packet Length Mean',
    'Subflow Fwd Bytes', 'Fwd Packet Length Mean', 'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Max Packet Length', 'Min Packet Length', 'Avg Fwd Segment Size', 'Fwd IAT Mean', 'Flow IAT Mean',
    'Flow Bytes/s', 'Fwd IAT Min', 'Fwd IAT Max', 'Flow IAT Min', 'Flow IAT Max', 'Flow Packets/s',
    'Flow Duration', 'Fwd Packets/s', 'Active Max', 'Idle Max']
LABEL = 'Label'

# Define benign and attacker IPs
BENIGN_IPS = ['192.168.1.10', '192.168.1.11']
ATTACKER_IPS = ['192.168.1.100', '192.168.1.101']
TARGET_IP = '192.168.1.1'
TARGET_PORT = 80

# Flow statistics storage
flow_stats = defaultdict(lambda: {
    feat: 0 for feat in FEATURES + [LABEL]
})
last_packet_time = {}  # Store last packet timestamp for each flow
last_active_time = {}  # Store last active time for idle calculation

start_time = None

# Function to process packets
def process_packet(packet):
    global start_time
    try:
        if 'IP' in packet and 'TCP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = 'TCP'
            timestamp = float(packet.sniff_time.timestamp())
            src_port = int(packet.tcp.srcport)
            dst_port = int(packet.tcp.dstport)
            pkt_length = int(packet.length)

            if start_time is None:
                start_time = timestamp

            # Flow Key includes src & dst IP and ports
            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

            # Initialize flow duration
            if flow_stats[flow_key]['Flow Duration'] == 0:
                flow_stats[flow_key]['Flow Duration'] = timestamp - start_time

            # Update flow statistics
            flow_stats[flow_key]['Subflow Fwd Bytes'] += pkt_length
            flow_stats[flow_key]['Fwd Packet Length Min'] = min(
                flow_stats[flow_key]['Fwd Packet Length Min'] or pkt_length, pkt_length)
            flow_stats[flow_key]['Fwd Packet Length Max'] = max(
                flow_stats[flow_key]['Fwd Packet Length Max'], pkt_length)
            flow_stats[flow_key]['Total Length of Fwd Packets'] += pkt_length

            # Packet arrival time stats (IAT - Inter-Arrival Time)
            if flow_key in last_packet_time:
                iat = timestamp - last_packet_time[flow_key]
                flow_stats[flow_key]['Fwd IAT Min'] = min(
                    flow_stats[flow_key]['Fwd IAT Min'] or iat, iat)
                flow_stats[flow_key]['Fwd IAT Max'] = max(
                    flow_stats[flow_key]['Fwd IAT Max'], iat)
                flow_stats[flow_key]['Flow IAT Min'] = min(
                    flow_stats[flow_key]['Flow IAT Min'] or iat, iat)
                flow_stats[flow_key]['Flow IAT Max'] = max(
                    flow_stats[flow_key]['Flow IAT Max'], iat)

            # Update last packet time
            last_packet_time[flow_key] = timestamp

            # Flow bytes & packets per second
            flow_stats[flow_key]['Flow Bytes/s'] = flow_stats[flow_key]['Total Length of Fwd Packets'] / (
                flow_stats[flow_key]['Flow Duration'] or 1)
            flow_stats[flow_key]['Flow Packets/s'] = len(flow_stats) / (
                flow_stats[flow_key]['Flow Duration'] or 1)

            # Active & Idle Time Calculations
            if flow_key in last_active_time:
                idle_time = timestamp - last_active_time[flow_key]
                flow_stats[flow_key]['Idle Max'] = max(
                    flow_stats[flow_key]['Idle Max'], idle_time)
            flow_stats[flow_key]['Active Max'] = timestamp - start_time
            last_active_time[flow_key] = timestamp  # Update last active time

            # Assign labels (Benign or DDoS)
            flow_stats[flow_key][LABEL] = 'DDoS' if src_ip in ATTACKER_IPS else 'Benign'
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to perform SYN Flood attack
def syn_flood():
    while True:
        for attacker_ip in ATTACKER_IPS:
            send(IP(src=attacker_ip, dst=TARGET_IP)/TCP(dport=TARGET_PORT, sport=RandShort(), flags='S'), count=5)
        time.sleep(0.1)

# Start SYN Flood in background
threading.Thread(target=syn_flood, daemon=True).start()

# Start packet capture
print(f"Capturing traffic for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)
start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Convert statistics to DataFrame & Save
df = pd.DataFrame(flow_stats.values())
df.to_csv(OUTPUT_CSV, index=False)
print(f"Traffic data saved to {OUTPUT_CSV}")

# Train HAT model
hat = HoeffdingAdaptiveTreeClassifier()
for _, row in df.iterrows():
    hat.learn_one(row[FEATURES], row[LABEL])

# Save model
with open(MODEL_FILE, "wb") as f:
    pickle.dump(hat, f)
print("HAT model trained and saved!")



