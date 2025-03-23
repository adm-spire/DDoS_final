import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.preprocessing import LabelEncoder
import numpy as np

# Step 1: Load the dataset
csv_file = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\captured_traffic_with_labels.csv"
data = pd.read_csv(csv_file)

# Step 2: Separate features and target
#X = data.drop(columns=['Label', 'Flow ID' , 'Timestamp' , 'Unnamed: 0','Source Port','Destination Port'])  # Replace ' Label' with the actual target column name
y = data['Label']

# Step 3: Handle infinite and large values
X = data.replace([np.inf, -np.inf], np.nan)  # Replace infinities with NaN
X = X.fillna(0)  # Fill NaN values with 0

# Optionally, cap very large values (e.g., above the 99th percentile)
for col in X.select_dtypes(include=[np.number]).columns:
    upper_limit = X[col].quantile(0.99)
    X[col] = np.clip(X[col], None, upper_limit)

# Step 4: Encode categorical columns
label_encoders = {}
for col in X.select_dtypes(include=['object', 'category']).columns:
    label_encoders[col] = LabelEncoder()
    X[col] = label_encoders[col].fit_transform(X[col].astype(str))

# Step 5: Fit ExtraTreesClassifier
model = ExtraTreesClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Step 6: Get feature importances
importances = model.feature_importances_

# Step 7: Sort and display the top 20 features
importance_df = pd.DataFrame({'Feature': X.columns, 'Importance': importances})
importance_df = importance_df.sort_values(by='Importance', ascending=False)

# Select top 20 features
top_10_features = importance_df.head(10)

# Step 8: Save to CSV
#output_csv = r"C:\Users\rauna\OneDrive\Desktop\ddos_final"
#top_10_features.to_csv(output_csv, index=False)
print(top_10_features)
#print(f"Top 20 feature importances saved to {output_csv}")