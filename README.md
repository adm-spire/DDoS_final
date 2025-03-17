# **DDoS_final**

## 📂 **File Description**

### 📡 **Data Capture**
- **`attack.py`** – Performs a **SYN flood attack** on the target.  
- **`attack2.py`** – Executes a **Slowloris attack** on the target.  
- **`benign.py`** – Sends **simple TCP/UDP packets** to the target (benign traffic).  
- **`live_target_capture_2.py`** – **Old version** of the main program for real-time predictions on network traffic.  
- **`live_target_capture_3.py`** – **New version** of the main program with **accuracy, precision, recall, and F1-score** calculations.  
- **`training_data_capture.py`** – Generates training data using a combination of **benign and attack traffic** and saves it as a **CSV file**.  

---

### 🔬 **Experimental**
- **`label_counter.py`** – Non-essential script used for analyzing the composition of predicted results.  

---

### ⚙ **Preprocessing**
- **`entropy_adaptive.py`** – **Key innovation in the project**:  
  - Prioritizes features that **increase entropy** while giving **lower weight** to unused features.  
- **`gradual_drift.py`** – Custom modification for handling **gradual concept drift**:  
  - **Resets subtrees** when **gradual attack pattern changes** are detected.  
  - **Built-in ADWIN** handles **instant pattern changes**.  
  - _(More details available on "Concept Drift" theory.)_  
- **`recurrant_drift.py`** – Custom modification for handling **recurrant concept drift**:
  - **`Re-trains model with old data`**  if accuracy of old data is over fixed threshold.
---

### ❌ **Redacted / Deprecated**
- **`live_traffic_capture.py`** – **Not in use** but saved for reference.  

---

### 🎯 **Training**
- **`training.py`** – Trains the model using the **saved training CSV file**.  
- **`hat_model.pkl`** – The trained **model saved in `.pkl` format** using Python's **pickle** library for future use.  

---

## 🔄 **Workflow**
training_data_capture.py → training.py → live_target_capture_3.py


---

## 📚 **Important Libraries Used**
- `scapy`, `pyshark`, `river`  

---

## 🤖 **Must-Know Models & Algorithms**
- **Hoeffding Bound & Hoeffding Tree** (Very Fast Decision Tree - VFDT)  
- **Entropy-based feature selection**  
- **Hoeffding Adaptive Tree (HAT)**  
- **Online learning models** (real-time adaptation)  
- **ADWIN Algorithm** (for drift detection)  
- **Concept Drift Types & Mitigation Techniques**  

---

### ✅ **Final Notes**
This project focuses on **real-time DDoS detection** using an **adaptive online machine learning model**. The **entropy-adaptive** preprocessing and **gradual drift detection** make it unique compared to standard **Hoeffding Adaptive Trees**.




