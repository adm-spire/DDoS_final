import pandas as pd
import pickle
from river import stream, tree, metrics

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

# Model save path
MODEL_PATH = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\hat_model.pkl"

# Check if a saved model exists
try:
    with open(MODEL_PATH, "rb") as f:
        hat = pickle.load(f)
    print("Loaded existing model from disk.")
except FileNotFoundError:
    hat = tree.HoeffdingAdaptiveTreeClassifier()
    print("No existing model found. Training a new one.")

# Define accuracy metric
accuracy = metrics.Accuracy()

# Train model incrementally
for x, y_true in data_stream:
    y_pred = hat.predict_one(x)  # Predict before training
    hat.learn_one(x, y_true)  # Train the model incrementally
    accuracy.update(y_true, y_pred)  # Update accuracy metric

# Print final accuracy
print(f"Final Accuracy: {accuracy.get():.4f}")

# Save the trained model using pickle
with open(MODEL_PATH, "wb") as f:
    pickle.dump(hat, f)

print(f"Model saved to {MODEL_PATH}")

