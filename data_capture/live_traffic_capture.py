import pyshark 
import pandas as pd
import numpy as np
import pickle
from collections import defaultdict
import time

# Load trained model
with open("hat_model.pkl", "rb") as f:
    hat = pickle.load(f)

print("Model loaded!")

# Define interface and parameters
INTERFACE = "Wi-Fi 2"
CAPTURE_DURATION = 60
OUTPUT_CSV = "captured_traffic_with_predictions.csv"

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
    "Subflow Fwd Bytes": 0
})

start_time = None

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

                # Compute inter-arrival times
                if last_time:
                    iat = timestamp - last_time
                    if src_ip == packet.ip.src:
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
                if src_ip == packet.ip.src:
                    flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)
                    flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
                    flow_stats[flow_key]["Subflow Fwd Bytes"] += pkt_length
                    if hasattr(packet[protocol], "flags") and int(getattr(packet[protocol], "flags", "0"), 16) & 0x10:
                        flow_stats[flow_key]["act_data_pkt_fwd"] += 1
                else:
                    flow_stats[flow_key]["Total Backward Packets"] += 1
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
    feature_vector["Prediction"] = hat.predict_one(feature_vector)
    data.append(feature_vector)

# Save to CSV
pd.DataFrame(data).to_csv(OUTPUT_CSV, index=False,float_format="%.10f")
print(f"Results saved to {OUTPUT_CSV}")
