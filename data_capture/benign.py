import socket
import time

def send_tcp(ip, port, message, count=10, delay=1):
    """Send TCP packets to a specified IP and port."""
    for _ in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.sendall(message.encode())
                print(f"Sent TCP: {message}")
        except Exception as e:
            print(f"TCP Error: {e}")
        time.sleep(delay)

def send_udp(ip, port, message, count=10, delay=1):
    """Send UDP packets to a specified IP and port."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for _ in range(count):
            try:
                s.sendto(message.encode(), (ip, port))
                print(f"Sent UDP: {message}")
            except Exception as e:
                print(f"UDP Error: {e}")
            time.sleep(delay)

# Example usage
TARGET_IP = "192.168.1.100"
TARGET_PORT = 8080
MESSAGE = "Hello from benign traffic!"

send_tcp(TARGET_IP, TARGET_PORT, MESSAGE)
send_udp(TARGET_IP, TARGET_PORT, MESSAGE)
