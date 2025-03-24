import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# File paths
CONF_MATRIX_CSV = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\confusion.csv"

# Load confusion matrix
df_conf_matrix = pd.read_csv(CONF_MATRIX_CSV, index_col=0)

# Plot confusion matrix
plt.figure(figsize=(6,5))
sns.heatmap(df_conf_matrix, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()


