import pyshark
import pandas as pd
import numpy as np
import pickle  
from collections import defaultdict
import time

# Load trained EFDT model
with open("hat_model.pkl", "rb") as f:
    hat = pickle.load(f)

print("HAT model loaded for real-time DDoS detection!")

# Define network interface & parameters
INTERFACE = "Wi-Fi 2"  
CAPTURE_DURATION = 60  
OUTPUT_CSV = "captured_traffic_with_predictions.csv"

# Initialize flow statistics storage
flow_stats = defaultdict(lambda: {
    "Start Time": None,
    "Last Packet Time": None,
    "Total Length of Fwd Packets": 0,
    "Fwd Packet Lengths": [],
    "Timestamps": [],
    "Prediction": "Unknown"
})

start_time = None  

# Function to process packets & classify them
def process_packet(packet):
    global start_time
    try:
        if "IP" in packet and ("TCP" in packet or "UDP" in packet):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer  
            timestamp = float(packet.sniff_time.timestamp())
            src_port = int(packet[protocol].srcport)
            dst_port = int(packet[protocol].dstport)
            pkt_length = int(packet.length)
            
            if start_time is None:
                start_time = timestamp  
            
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
            
            if flow_stats[flow_key]["Start Time"] is None:
                flow_stats[flow_key]["Start Time"] = timestamp - start_time  
            
            flow_stats[flow_key]["Total Length of Fwd Packets"] += pkt_length
            flow_stats[flow_key]["Fwd Packet Lengths"].append(pkt_length)
            flow_stats[flow_key]["Timestamps"].append(timestamp - start_time)
            
            # Flow Duration
            flow_stats[flow_key]["Flow Duration"] = (timestamp - start_time) - flow_stats[flow_key]["Start Time"]
            
            # Flow Bytes/s
            flow_stats[flow_key]["Flow Bytes/s"] = (flow_stats[flow_key]["Total Length of Fwd Packets"] /
                                                     flow_stats[flow_key]["Flow Duration"]
                                                     if flow_stats[flow_key]["Flow Duration"] > 0 else 0)
            
            # Flow Packets/s
            flow_stats[flow_key]["Flow Packets/s"] = (len(flow_stats[flow_key]["Fwd Packet Lengths"]) /
                                                       flow_stats[flow_key]["Flow Duration"]
                                                       if flow_stats[flow_key]["Flow Duration"] > 0 else 0)
            
            # IAT statistics
            if len(flow_stats[flow_key]["Timestamps"]) > 1:
                iats = np.diff(flow_stats[flow_key]["Timestamps"])
                flow_stats[flow_key]["Fwd IAT Mean"] = np.mean(iats)
                flow_stats[flow_key]["Fwd IAT Min"] = np.min(iats)
                flow_stats[flow_key]["Fwd IAT Max"] = np.max(iats)
            
            # Active and Idle Time Calculation
            if len(flow_stats[flow_key]["Timestamps"]) > 1:
                deltas = np.diff(flow_stats[flow_key]["Timestamps"])
                active_times = deltas[deltas < 1]  
                idle_times = deltas[deltas >= 1]   
                flow_stats[flow_key]["Active Max"] = np.max(active_times) if len(active_times) > 0 else 0
                flow_stats[flow_key]["Idle Max"] = np.max(idle_times) if len(idle_times) > 0 else 0
            
            # Features for classification
            features = {
                "Average Packet Size": (flow_stats[flow_key]["Total Length of Fwd Packets"] /
                                         len(flow_stats[flow_key]["Fwd Packet Lengths"])
                                         if flow_stats[flow_key]["Fwd Packet Lengths"] else 0),
                "Fwd Packet Length Min": np.min(flow_stats[flow_key]["Fwd Packet Lengths"])
                                        if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Packet Length Mean": np.mean(flow_stats[flow_key]["Fwd Packet Lengths"])
                                      if flow_stats[flow_key]["Fwd Packet Lengths"] else 0,
                "Subflow Fwd Bytes": flow_stats[flow_key]["Total Length of Fwd Packets"],
                "Fwd Packet Length Mean": (flow_stats[flow_key]["Total Length of Fwd Packets"] /
                                            len(flow_stats[flow_key]["Fwd Packet Lengths"])
                                            if flow_stats[flow_key]["Fwd Packet Lengths"] else 0),
                "Total Length of Fwd Packets": flow_stats[flow_key]["Total Length of Fwd Packets"],
                "Flow Bytes/s": flow_stats[flow_key]["Flow Bytes/s"],
                "Flow Packets/s": flow_stats[flow_key]["Flow Packets/s"],
                "Flow Duration": flow_stats[flow_key]["Flow Duration"],
                "Fwd IAT Mean": flow_stats[flow_key]["Fwd IAT Mean"],
                "Fwd IAT Min": flow_stats[flow_key]["Fwd IAT Min"],
                "Fwd IAT Max": flow_stats[flow_key]["Fwd IAT Max"],
                "Active Max": flow_stats[flow_key]["Active Max"],
                "Idle Max": flow_stats[flow_key]["Idle Max"]
            }
            
            prediction = hat.predict_one(features)
            flow_stats[flow_key]["Prediction"] = prediction  
            print(f"Packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port} classified as: {prediction}")

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start packet capture & classification
print(f"Starting real-time DDoS detection on interface {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE)

start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Convert statistics into DataFrame & Save Results
data = [{**stats} for stats in flow_stats.values()]
df = pd.DataFrame(data)
df.to_csv(OUTPUT_CSV, index=False)
print(f"DDoS detection completed. Results saved to {OUTPUT_CSV}")




