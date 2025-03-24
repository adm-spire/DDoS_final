import pandas as pd

# Load the CSV file
input_file = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\captured_traffic_with_labels.csv"
output_file = r"C:\Users\rauna\OneDrive\Desktop\ddos_final\captured_traffic_with_labels_2.csv"

# Read the CSV
df = pd.read_csv(input_file)

# Remove rows where "Label" is "nil"
df_filtered = df[df["Label"] != "nil"]

# Save the filtered data to a new CSV
df_filtered.to_csv(output_file, index=False)

print(f"Filtered CSV saved as {output_file}")
