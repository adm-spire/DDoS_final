import pandas as pd
import pickle
from river import stream, tree, metrics 
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from preprocessing import HybridHat


# Load CSV file
CSV_FILE = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\captured_traffic_with_labels.csv"  # CSV file

# Define the target column 
TARGET_COLUMN = "Label"  # target column

# Read CSV into a Pandas DataFrame
df = pd.read_csv(CSV_FILE)

# Separate features (X) and target (y)
X = df.drop(columns=[TARGET_COLUMN])  # Feature columns
y = df[TARGET_COLUMN]  # Target column

# Convert data into a River-compatible stream
data_stream = stream.iter_pandas(X, y)

#combined  custom classes 



# Model save path
MODEL_PATH = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\hat_model.pkl"

# model training

#hat = tree.HoeffdingAdaptiveTreeClassifier()
hat = HybridHat.HybridHAT() 
print("No existing model found. Training a new one.")

# Define multiple metrics
accuracy = metrics.Accuracy()


# Train model incrementally
for x, y_true in data_stream:
    y_pred = hat.predict_one(x)  # Predict before training
    hat.learn_one(x, y_true)  # Train the model incrementally
    
    # Update all metrics
    accuracy.update(y_true, y_pred)
    
    


# Print final metrics
print(f"Final Accuracy: {accuracy.get():.4f}")



# Save the trained model using pickle
with open(MODEL_PATH, "wb") as f:
    pickle.dump(hat, f)

print(f"Model saved to {MODEL_PATH}")

