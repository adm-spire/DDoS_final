import socket
import time
import threading

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

TARGET_HOSTNAME = "raspberrypi.local"  # Hostname
TARGET_IP = socket.gethostbyname(TARGET_HOSTNAME)  # Converts hostname to IP
TARGET_PORT = 8080
MESSAGE = "Hello from benign traffic!"

# Run UDP sender in a separate thread
udp_thread = threading.Thread(target=send_udp, args=(TARGET_IP, TARGET_PORT, MESSAGE))
udp_thread.start()
udp_thread.join()


