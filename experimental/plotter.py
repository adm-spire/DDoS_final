import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import auc

# List of CSV files containing ROC and PRC data
roc_files = [
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\roc_01.csv",
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\roc_02.csv",
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\roc_03.csv"
]
prc_files = [
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\prc_01.csv",
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\prc_02.csv",
    r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\prc_03.csv"
]

# Labels for each curve
labels = ["attack prob - 0.8", "attack prob - 0.95", "attack prob - 0.5"]

# Line styles for each curve
line_styles = ["-", "--", ":"]  # Solid, Dashed, Dotted

# Plot ROC curves
plt.figure(figsize=(12, 5))

# Subplot for ROC curves
plt.subplot(1, 2, 1)
for i, (file, label, linestyle) in enumerate(zip(roc_files, labels, line_styles)):
    roc_data = pd.read_csv(file)
    fpr = roc_data["FPR"]
    tpr = roc_data["TPR"]
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, linestyle=linestyle, lw=2, label=f'{label} (AUC = {roc_auc:.2f})')

plt.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--')  # Diagonal line
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate (FPR)')
plt.ylabel('True Positive Rate (TPR)')
plt.title('Receiver Operating Characteristic (ROC) Curves')
plt.legend(loc="lower right")

# Subplot for PRC curves
plt.subplot(1, 2, 2)
for i, (file, label, linestyle) in enumerate(zip(prc_files, labels, line_styles)):
    prc_data = pd.read_csv(file)
    precisions = prc_data["Precision"]
    recalls = prc_data["Recall"]
    prc_auc = auc(recalls, precisions)
    plt.plot(recalls, precisions, linestyle=linestyle, lw=2, label=f'{label} (AUC = {prc_auc:.2f})')

plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curves (PRC)')
plt.legend(loc="lower left")

plt.tight_layout()
plt.show()