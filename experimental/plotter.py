import pandas as pd
import matplotlib.pyplot as plt

# Load rolling metrics
rolling_metrics = pd.read_csv(r"C:\Users\rauna\OneDrive\Desktop\ddos_final\files\rolling_metrics.csv")



# Plot Rolling Accuracy
plt.figure(figsize=(10, 5))
plt.plot(rolling_metrics["Index"], rolling_metrics["Rolling Accuracy"], label="Rolling Accuracy", color="blue")
plt.xlabel("Time (Instances)")
plt.ylabel("Accuracy")
plt.title("Rolling Accuracy Over Time")
plt.legend()
plt.grid(True)
plt.savefig("rolling_accuracy.png")
plt.show()

# Plot Precision, Recall, and F1-Score
plt.figure(figsize=(10, 5))
plt.plot(rolling_metrics["Index"], rolling_metrics["Rolling Precision"], label="Precision", color="green")
plt.plot(rolling_metrics["Index"], rolling_metrics["Rolling Recall"], label="Recall", color="red")
plt.plot(rolling_metrics["Index"], rolling_metrics["Rolling F1-Score"], label="F1-Score", color="purple")
plt.xlabel("Time (Instances)")
plt.ylabel("Score")
plt.title("Precision, Recall, and F1-Score Over Time")
plt.legend()
plt.grid(True)
plt.savefig("rolling_prf1.png")
plt.show()


