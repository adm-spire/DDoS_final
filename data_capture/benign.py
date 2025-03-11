import socket
import time

def send_tcp(ip, port, message, delay=1):
    """Send TCP packets indefinitely to a specified IP and port."""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, port))
                s.sendall(message.encode())
                print(f"Sent TCP: {message}")
        except Exception as e:
            print(f"TCP Error: {e}")
        time.sleep(delay)

def send_udp(ip, port, message, delay=1):
    """Send UDP packets indefinitely to a specified IP and port."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            try:
                s.sendto(message.encode(), (ip, port))
                print(f"Sent UDP: {message}")
            except Exception as e:
                print(f"UDP Error: {e}")
            time.sleep(delay)


TARGET_HOSTNAME = "raspberrypi.local"  # hostname
TARGET_IP = socket.gethostbyname(TARGET_HOSTNAME)  # Converts hostname to IP
TARGET_PORT = 8080
MESSAGE = "Hello from benign traffic!"

# Run both functions indefinitely 
import threading

tcp_thread = threading.Thread(target=send_tcp, args=(TARGET_IP, TARGET_PORT, MESSAGE))
udp_thread = threading.Thread(target=send_udp, args=(TARGET_IP, TARGET_PORT, MESSAGE))

tcp_thread.start()
udp_thread.start()

tcp_thread.join()
udp_thread.join()

