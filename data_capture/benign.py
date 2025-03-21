import socket
import time
import threading
import random

TARGET_IP = "192.168.43.108"
MESSAGE = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
MIN_DELAY = 0.1
MAX_DELAY = 1.0  # Randomized delay range

def send_tcp_request():
    """Simulate HTTP requests to test robustness against false positives."""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((TARGET_IP, 80))
                s.sendall(MESSAGE.encode())
                response = s.recv(1024)
                print(f"Received TCP response: {response[:50]}...")
        except Exception as e:
            print(f"TCP Error: {e}")
        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

def send_udp():
    """Send UDP packets with varying ports and content."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            try:
                port = random.randint(1, 65535)
                random_payload = f"User-{random.randint(1, 100)}: {MESSAGE}"
                s.sendto(random_payload.encode(), (TARGET_IP, port))
                print(f"Sent UDP to {port}")
            except Exception as e:
                print(f"UDP Error: {e}")
            time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))

# Run benign traffic in parallel
threads = [
    threading.Thread(target=send_tcp_request),
    threading.Thread(target=send_udp)
]

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()




