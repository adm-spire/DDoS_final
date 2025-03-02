import pandas as pd
import pickle
from river import tree, stream, drift
import collections

# Load dataset 
DATASET_PATH = r"C:\Users\rauna\OneDrive\Desktop\DDOS_upgraded\dataset\stripped_custom.csv"

# Select features & labels
FEATURES = [ 'Average Packet Size', 'Fwd Packet Length Min', 'Packet Length Mean',
    'Subflow Fwd Bytes', 'Fwd Packet Length Mean', 'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Max Packet Length', 'Min Packet Length', 'Avg Fwd Segment Size', 'Fwd IAT Mean', 'Flow IAT Mean',
    'Flow Bytes/s', 'Fwd IAT Min', 'Fwd IAT Max', 'Flow IAT Min', 'Flow IAT Max', 'Flow Packets/s',
    'Flow Duration', 'Fwd Packets/s']
LABEL = 'Label'

# Load dataset as a stream
df = pd.read_csv(DATASET_PATH)
data_stream = stream.iter_pandas(df[FEATURES], df[LABEL])

# Initialize EFDT with modifications
model = tree.HoeffdingAdaptiveTreeClassifier(
    grace_period=100,
    delta=1e-5,
    leaf_prediction='nb',
    nb_threshold=10,
    seed=0
)

print("Training HAT model...")
for x, y in data_stream:
    model.learn_one(x, y)




print("Training complete!")

# Save trained HAT model
with open("hat_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("Model saved as 'hat_model.pkl'")


