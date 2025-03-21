import pyshark
import pandas as pd
import numpy as np
import pickle
from collections import defaultdict
import time
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, 
                             roc_auc_score, average_precision_score, confusion_matrix, 
                             roc_curve, precision_recall_curve)
import sys
import os



sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from preprocessing import HybridHat

# Load trained model
with open("hat_model.pkl", "rb") as f:
    hat = pickle.load(f)

print("Model loaded!")

# Define interface and parameters
INTERFACE = "Wi-Fi 2"
CAPTURE_DURATION = 60
OUTPUT_CSV = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\captured_traffic_with_predictions.csv"
CONF_MATRIX_CSV = "confusion_matrix_data.csv"
ROC_CSV = "roc_curve_data.csv"
PRC_CSV = "prc_curve_data.csv"
TARGET_IP = "192.168.43.108"

bpf_filter = f"(udp or (tcp and tcp[tcpflags] & tcp-syn != 0)) and dst host {TARGET_IP}"


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
    except Exception as e:
        print(f"Error processing packet: {e}")

# Start capture
print(f"Capturing on {INTERFACE} for {CAPTURE_DURATION} seconds...")
capture = pyshark.LiveCapture(interface=INTERFACE,bpf_filter=bpf_filter)

start_time = time.time()
for packet in capture.sniff_continuously():
    if time.time() - start_time > CAPTURE_DURATION:
        break
    process_packet(packet)

# Compute features and model predictions
data = []
ground_truth = []
predictions = []
probs = []

for flow_key, stats in flow_stats.items():
    src_ip = flow_key[0]
    #benign = 0
    #attack = 1
  

    true_label = 0 if src_ip == "192.168.43.109" else 1
    ground_truth.append(true_label)

    duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-6)  # Prevent zero duration

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
    }

    prediction_prob = hat.predict_proba_one(feature_vector)  # Returns a dictionary

    # Extract the probability of the "attack" class 
    attack_prob = prediction_prob.get("attack", 0)  # Default to 0 if key is missing

    prediction = 1 if attack_prob > 0.8 else 0  # Thresholding

    if prediction == 1:
        feature_vector["Prediction"] = "attack"
    else:
        feature_vector["Prediction"] = "benign"


    feature_vector["Attack Probability"] = attack_prob
    feature_vector["source_ip"] = src_ip

    predictions.append(prediction)
    probs.append(attack_prob)  # Store probability for ROC/PRC curves

    

    # Append feature vector to `data`
    data.append(feature_vector)


# Save results
pd.DataFrame(data).to_csv(OUTPUT_CSV, index=False)

# Compute metrics
conf_matrix = confusion_matrix(ground_truth, predictions)
(TN, FP), (FN, TP) = conf_matrix
specificity = TN / (TN + FP)
balanced_acc = (recall_score(ground_truth, predictions) + specificity) / 2
g_mean = np.sqrt(recall_score(ground_truth, predictions) * specificity)
auc_roc = roc_auc_score(ground_truth, probs)
auc_prc = average_precision_score(ground_truth, probs)

# Additional metrics
accuracy = accuracy_score(ground_truth, predictions)
precision = precision_score(ground_truth, predictions)
recall = recall_score(ground_truth, predictions)
f1 = f1_score(ground_truth, predictions)

# Save confusion matrix data
pd.DataFrame(conf_matrix, index=["Actual 0", "Actual 1"], columns=["Predicted 0", "Predicted 1"]).to_csv(CONF_MATRIX_CSV)

# Compute and save ROC curve
fpr, tpr, thresholds = roc_curve(ground_truth, probs)
pd.DataFrame({"FPR": fpr, "TPR": tpr, "Thresholds": thresholds}).to_csv(ROC_CSV, index=False)

# Compute and save PRC curve
precisions, recalls, prc_thresholds = precision_recall_curve(ground_truth, probs)
pd.DataFrame({"Precision": precisions, "Recall": recalls, "Thresholds": np.append(prc_thresholds, np.nan)}).to_csv(PRC_CSV, index=False)

# Print results
print(f"Accuracy: {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall: {recall:.4f}")
print(f"F1 Score: {f1:.4f}")
print(f"Specificity: {specificity:.4f}")
print(f"Balanced Accuracy: {balanced_acc:.4f}")
print(f"G-Mean: {g_mean:.4f}")
print(f"AUC-ROC: {auc_roc:.4f}")
print(f"AUC-PRC: {auc_prc:.4f}")
print(f"Confusion Matrix saved to {CONF_MATRIX_CSV}")
print(f"ROC curve data saved to {ROC_CSV}")
print(f"PRC curve data saved to {PRC_CSV}")




















