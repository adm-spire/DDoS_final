import socket
import time
import threading
import random
import scapy.all as scapy

# Target
TARGET_IP = "192.168.43.108"
MESSAGE = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
MIN_DELAY = 0.01
MAX_DELAY = 0.1  # Randomized delay range

# Fixed benign IPs
BENIGN_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30", "192.168.1.40",
    "192.168.1.50", "192.168.1.60", "192.168.1.70", "192.168.1.80",
    "192.168.1.90", "192.168.1.100"
]

# Duration before switching to another benign IP
BENIGN_SESSION_TIME = random.uniform(5, 10)  


def send_tcp_request():
    """Simulate HTTP requests with a single IP maintaining connection for some time before switching."""
    while True:
        selected_ip = random.choice(BENIGN_IPS)
        start_time = time.time()

        while time.time() - start_time < BENIGN_SESSION_TIME:
            try:
                sport = random.randint(1024, 1055)  # Random source port
                
                

                # Construct TCP packet with Scapy
                ip = scapy.IP(src=selected_ip, dst=TARGET_IP)
                tcp = scapy.TCP(sport=sport, dport=80, flags="PA")
                payload = scapy.Raw(load=MESSAGE)

                packet = ip / tcp / payload
                scapy.send(packet, verbose=False)

                print(f"Sent TCP request from {selected_ip}")

            except Exception as e:
                print(f"TCP Error: {e}")

            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

        print(f"Switching TCP benign IP from {selected_ip} to a new one.")


def send_udp():
    """Send UDP packets with a single IP maintaining connection for some time before switching."""
    while True:
        selected_ip = random.choice(BENIGN_IPS)
        start_time = time.time()
        udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900, 4500, 5353, 6481, 10000, 33434]
        while time.time() - start_time < BENIGN_SESSION_TIME:
            try:
                sport = random.randint(1024, 1040)
                port = random.choice(udp_ports)
                random_payload = f"User-{random.randint(1, 100)}: {MESSAGE}"

                ip = scapy.IP(src=selected_ip, dst=TARGET_IP)
                udp = scapy.UDP(sport=sport, dport=port)
                payload = scapy.Raw(load=random_payload)

                packet = ip / udp / payload
                scapy.send(packet, verbose=False)

                print(f"Sent UDP from {selected_ip} to port {port}")

            except Exception as e:
                print(f"UDP Error: {e}")

            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

        print(f"Switching UDP benign IP from {selected_ip} to a new one.")


# Run benign traffic in parallel
threads = [
    threading.Thread(target=send_tcp_request, daemon=True),
    #threading.Thread(target=send_udp, daemon=True)
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()






