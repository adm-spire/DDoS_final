import pandas as pd

# Load the CSV file
csv_file =  r"C:\Users\rauna\OneDrive\Desktop\ddos_final\captured_traffic_with_labels.csv" # CSV file 
df = pd.read_csv(csv_file)

# Count occurrences of "attack" and "benign" in the "Label" column
attack_count = (df["Label"] == "attack").sum()
benign_count = (df["Label"] == "benign").sum()

# Print the results
print(f"Number of 'attack' rows: {attack_count}")
print(f"Number of 'benign' rows: {benign_count}")
