import pyshark
import pandas as pd
import numpy as np
import pickle  # To load the trained EFDT model
from collections import defaultdict
import time

#  Load trained EFDT model
with open("efdt_model.pkl", "rb") as f:
    efdt = pickle.load(f)

print("EFDT model loaded for real-time DDoS detection!")

#  Define network interface & parameters
INTERFACE = "Wi-Fi 2"  # network interface
CAPTURE_DURATION = 60  # Capture time in seconds
OUTPUT_CSV = "captured_traffic_with_predictions.csv"

#  Initialize flow statistics storage
flow_stats = defaultdict(lambda: {
    "Source IP": "",
    "Source Port": 0,
    "Flow Duration": 0,
    "Total Length of Fwd Packets": 0,
    "Fwd Packet Lengths": [],
    "Flow IATs": [],
    "Fwd IATs": [],
    "Flow Bytes/s": 0,
    "Flow Packets/s": 0,
    "Fwd Packets/s": 0,
    "Start Time": None,
    "Last Packet Time": None,
    "Average Packet Size": 0,
    "Prediction": "Unknown"  # Stores EFDT classification result
})

#  Function to process packets & classify them
def process_packet(packet):
    try:
        if "IP" in packet and ("TCP" in packet or "UDP" in packet):
            src_ip = packet.ip.src
            protocol = packet.transport_layer  # TCP/UDP
            timestamp = float(packet.sniff_time.timestamp())
            src_port = int(packet[protocol].srcport)
            pkt_length = int(packet.length)
            
            # Identify the flow key
            flow_key = (src_ip, src_port, protocol)
            
            # Initialize flow start time
            if flow_stats[flow_key]["Start Time"] is None:
                flow_stats[flow_key]["Start Time"] = timestamp
            
            # Compute flow duration
            flow_stats[flow_key]["Flow Duration"] = timestamp - flow_stats[flow_key]["Start Time"]

            # Update flow statistics
            flow_stats[flow_key]["Source IP"] = src_ip
            flow_stats[flow_key]["Source Port"] = src_port

            # Compute Inter-Arrival Time (IAT)
            if flow_stats[flow_key]["Last Packet Time"] is not None:
                iat = timestamp - flow_stats[flow_key]["Last Packet Time"]
                flow_stats[flow_key]["Flow IATs"].append(iat)
                flow_stats[flow_key]["Fwd IATs"].append(iat)

            # Update packet lengths
            flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
            flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)

            # Compute Flow Bytes/sec
            if flow_stats[flow_key]["Flow Duration"] > 0:
                flow_stats[flow_key]["Flow Bytes/s"] = flow_stats[flow_key]["Total Length of Fwd Packets"] / flow_stats[flow_key]["Flow Duration"]

            # Compute Average Packet Size
            if flow_stats[flow_key]["Fwd Packet Lengths"]:
                flow_stats[flow_key]["Average Packet Size"] = flow_stats[flow_key]["Total Length of Fwd Packets"] / len(flow_stats[flow_key]["Fwd Packet Lengths"])
            
            # Update last packet time
            flow_stats[flow_key]["Last Packet Time"] = timestamp

            #  Extract features for EFDT inference
            features = {
                "Average Packet Size": flow_stats[flow_key]["Average Packet Size"],
                "Fwd Packet Length Min": np.min(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Packet Length Mean": np.mean(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Subflow Fwd Bytes": flow_stats[flow_key]["Total Length of Fwd Packets"],
                "Fwd Packet Length Mean": flow_stats[flow_key]["Total Length of Fwd Packets"] / len(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Total Length of Fwd Packets": flow_stats[flow_key]["Total Length of Fwd Packets"],
                "Fwd Packet Length Max": np.max(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Max Packet Length": np.max(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Min Packet Length": np.min(flow_stats[flow_key]["Fwd Packet Lengths"]) if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Flow Bytes/s": flow_stats[flow_key]["Flow Bytes/s"],
                "Flow Packets/s": len(flow_stats[flow_key]["Fwd Packet Lengths"]) / flow_stats[flow_key]["Flow Duration"] if flow_stats[flow_key]["Flow Duration"] > 0 else 0,
                "Flow Duration": flow_stats[flow_key]["Flow Duration"]
            }

            #  Perform real-time inference
            prediction = efdt.predict_one(features)
            flow_stats[flow_key]["Prediction"] = prediction  # Store prediction result
            print(f"Packet from {src_ip}:{src_port} classified as: {prediction}")

    except Exception as e:
        print(f"Error processing packet: {e}")

#  Start packet capture & classification
print(f"Starting real-time DDoS detection on interface {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)

#  Capture packets for a fixed duration
start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

#  Convert statistics into DataFrame & Save Results
data = []
for flow_key, stats in flow_stats.items():
    data.append(stats)

df = pd.DataFrame(data)

#  Save results to CSV (with predictions)
df.to_csv(OUTPUT_CSV, index=False)
print(f"DDoS detection completed. Results saved to {OUTPUT_CSV}")
