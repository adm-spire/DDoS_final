import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# File paths
CONF_MATRIX_CSV = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\confusion.csv"
ROC_CSV = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\roc.csv"
PRC_CSV = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\prc.csv"

# Load confusion matrix
df_conf_matrix = pd.read_csv(CONF_MATRIX_CSV, index_col=0)

# Load ROC curve
df_roc = pd.read_csv(ROC_CSV)

# Load PRC curve
df_prc = pd.read_csv(PRC_CSV)

# Plot confusion matrix
plt.figure(figsize=(6,5))
sns.heatmap(df_conf_matrix, annot=True, fmt="d", cmap="Blues")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()

# Plot ROC curve
plt.figure(figsize=(6,5))
plt.plot(df_roc["FPR"], df_roc["TPR"], label="ROC Curve")
plt.plot([0, 1], [0, 1], linestyle="--", color="gray", label="Random Guess")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Receiver Operating Characteristic (ROC) Curve")
plt.legend()
plt.show()

# Plot PRC curve
plt.figure(figsize=(6,5))
plt.plot(df_prc["Recall"], df_prc["Precision"], label="PRC Curve")
plt.xlabel("Recall")
plt.ylabel("Precision")
plt.title("Precision-Recall Curve")
plt.legend()
plt.show()