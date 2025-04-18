import pyshark 
import pandas as pd
import numpy as np
import pickle
from collections import defaultdict
import time
import matplotlib.pyplot as plt
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_curve, auc, precision_recall_curve, average_precision_score,
    balanced_accuracy_score, confusion_matrix
)
from math import sqrt
from preprocessing import HybridHat
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

            # Ensure transport_layer is valid
            protocol = packet.transport_layer
            if protocol is None:
                return  # Skip packet if transport_layer is missing

            timestamp = float(packet.sniff_time.timestamp())

            if hasattr(packet[protocol], "srcport") and hasattr(packet[protocol], "dstport"):
                src_port = int(getattr(packet[protocol], "srcport", 0))
                dst_port = int(getattr(packet[protocol], "dstport", 0))
                pkt_length = int(getattr(packet, "length", 0))

                if start_time is None:
                    start_time = timestamp

                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

                if flow_key not in flow_stats:
                    flow_stats[flow_key] = {
                        "Start Time": None,
                        "Last Packet Time": None,
                        "Fwd IATs": [],
                        "Bwd IATs": [],
                        "Active Times": [],
                        "Idle Times": [],
                        "Packet Lengths": [],
                        "Fwd Packet Lengths": [],
                        "Total Length of Fwd Packets": 0,
                        "Subflow Fwd Bytes": 0,
                        "act_data_pkt_fwd": 0,
                        "Total Backward Packets": 0
                    }

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

                    # Check if flags attribute exists before accessing it
                    if hasattr(packet[protocol], "flags"):
                        flags = getattr(packet[protocol], "flags", None)
                        if flags is not None and isinstance(flags, str) and int(flags, 16) & 0x10:
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

probabilities = []
ground_truth = []

for flow_key, stats in flow_stats.items():
    src_ip = flow_key[0]  # Extract source IP

    duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-6)  # Prevent zero duration
    feature_vector = {
        "Flow Duration": duration,
        "Flow Bytes/s": stats["Total Length of Fwd Packets"] / duration,
        "Flow Packets/s": len(stats["Packet Lengths"]) / duration,
        "Fwd Packet Length Min": min(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
        "Fwd Packet Length Max": max(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
        "Fwd Packet Length Mean": np.mean(stats["Fwd Packet Lengths"]) if stats["Fwd Packet Lengths"] else 0,
        "Packet Length Std": np.std(stats["Packet Lengths"]) if stats["Packet Lengths"] else 0,
        "Active Mean": np.mean(stats["Active Times"]) if stats["Active Times"] else 0,
        "Idle Mean": np.mean(stats["Idle Times"]) if stats["Idle Times"] else 0,
        "Total Length of Fwd Packets": stats["Total Length of Fwd Packets"],
        "Total Backward Packets": stats["Total Backward Packets"]
    }

    # Get model prediction probability
    prob = hat.predict_proba_one(feature_vector)
    attack_prob = prob.get("attack", 0.0)  # Probability of attack class
    
    probabilities.append(attack_prob)

    # Ground truth assignment
    true_label = 0 if src_ip == "172.20.189.54" else 1  # 0 for benign, 1 for attack
    ground_truth.append(true_label)

# Compute ROC curve
fpr, tpr, _ = roc_curve(ground_truth, probabilities)
roc_auc = auc(fpr, tpr)

# Compute PR curve and AUC-PR score
precision, recall, _ = precision_recall_curve(ground_truth, probabilities)
auc_pr = average_precision_score(ground_truth, probabilities)

# Compute evaluation metrics
predictions = [1 if p > 0.5 else 0 for p in probabilities]
accuracy = accuracy_score(ground_truth, predictions)
precision_score_value = precision_score(ground_truth, predictions)
recall_score_value = recall_score(ground_truth, predictions)
f1 = f1_score(ground_truth, predictions)

# Compute confusion matrix values
tn, fp, fn, tp = confusion_matrix(ground_truth, predictions).ravel()
specificity = tn / (tn + fp)  # True Negative Rate
g_mean = sqrt(recall_score_value * specificity)  # Geometric Mean
balanced_accuracy = balanced_accuracy_score(ground_truth, predictions)  # Balanced Accuracy

# Print metrics
print(f"AUC-ROC: {roc_auc:.4f}")
print(f"AUC-PR: {auc_pr:.4f}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision_score_value:.4f}")
print(f"Recall: {recall_score_value:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"Specificity: {specificity:.4f}")
print(f"G-Mean: {g_mean:.4f}")
print(f"Balanced Accuracy: {balanced_accuracy:.4f}")

# Plot PR Curve
'''
plt.figure(figsize=(8, 6))
plt.plot(recall, precision, color="red", lw=2, label=f"PR curve (AUC = {auc_pr:.2f})")
plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title("Precision-Recall Curve")
plt.legend(loc="lower left")
plt.show()'
'''
