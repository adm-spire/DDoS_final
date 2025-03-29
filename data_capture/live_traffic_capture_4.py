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
    "Label": "benign"
})
start_time = None

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

# Compute features and model predictions
data = []
ground_truth = []
predictions = []
probs = []

BENIGN_USERS = {
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.80",
    "192.168.1.90", "192.168.1.100"
}

for flow_key, stats in flow_stats.items():
    src_ip = flow_key[0]
    #benign = 0
    #attack = 1
  

    true_label = 0 if src_ip in BENIGN_USERS else 1
    ground_truth.append(true_label)

    

for flow_key, stats in flow_stats.items():
    duration = max((stats["Last Packet Time"] - stats["Start Time"]), 1e-10)
    #print(f"Flow {flow_key}: Start Time = {flow_stats[flow_key]['Start Time']}, Last Packet Time = {flow_stats[flow_key]['Last Packet Time']}, Duration = {duration}")
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

pd.DataFrame(conf_matrix, index=["Actual 0", "Actual 1"], columns=["Predicted 0", "Predicted 1"]).to_csv(CONF_MATRIX_CSV)

# Ensure predictions and ground_truth are NumPy arrays
predictions = np.array(predictions)  # Convert to NumPy array if not already
ground_truth = np.array(ground_truth)  # Convert to NumPy array if not already

window_size = 100  # Define a window for moving accuracy

# Compute rolling accuracy safely
rolling_accuracy = [
    np.mean(predictions[max(0, i - window_size): i]) if i >= window_size else np.nan
    for i in range(len(predictions))
]

# Compute rolling precision, recall, and F1-score safely
rolling_precision = [
    precision_score(ground_truth[:i], predictions[:i], zero_division=0) if i > 0 else np.nan
    for i in range(len(predictions))
]

rolling_recall = [
    recall_score(ground_truth[:i], predictions[:i], zero_division=0) if i > 0 else np.nan
    for i in range(len(predictions))
]

rolling_f1 = [
    f1_score(ground_truth[:i], predictions[:i], zero_division=0) if i > 0 else np.nan
    for i in range(len(predictions))
]




# Save rolling metrics to CSV
rolling_metrics = pd.DataFrame({
    "Index": list(range(len(predictions))),
    "Rolling Accuracy": rolling_accuracy,
    "Rolling Precision": rolling_precision,
    "Rolling Recall": rolling_recall,
    "Rolling F1-Score": rolling_f1
})
rolling_metrics.to_csv("rolling_metrics.csv", index=False)




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
print("Rolling metrics  saved to CSV.")





















