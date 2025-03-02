import pandas as pd
import pickle  # To save the trained model
from river import tree, stream

# 📌 Load dataset 
DATASET_PATH = r"C:\Users\rauna\OneDrive\Desktop\DDOS_upgraded\dataset\stripped_custom.csv"

#  Select relevant features and labels
FEATURES = [ 'Average Packet Size', 'Fwd Packet Length Min', 'Packet Length Mean',
    'Subflow Fwd Bytes', 'Fwd Packet Length Mean', 'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Max Packet Length', 'Min Packet Length', 'Avg Fwd Segment Size', 'Fwd IAT Mean', 'Flow IAT Mean',
    'Flow Bytes/s', 'Fwd IAT Min', 'Fwd IAT Max', 'Flow IAT Min', 'Flow IAT Max', 'Flow Packets/s',
    'Flow Duration', 'Fwd Packets/s', ]
LABEL = 'Label'

#  Load dataset as a stream
df = pd.read_csv(DATASET_PATH)
data_stream = stream.iter_pandas(df[FEATURES], df[LABEL])

# Initialize EFDT model
efdt = tree.ExtremelyFastDecisionTreeClassifier()

# Train EFDT model on streaming data
print("Training EFDT model...")
for x, y in data_stream:
    efdt.learn_one(x, y)

print("Training complete!")

# Save trained EFDT model
with open("efdt_model.pkl", "wb") as f:
    pickle.dump(efdt, f)

print("Model saved as 'efdt_model.pkl'")
