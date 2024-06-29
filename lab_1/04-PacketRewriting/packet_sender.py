import socket
import time

UDP_IP = "10.0.0.1"
UDP_PORT = 25565
UDP_MSG = "Ciaone"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
while(True):
    print("Sending packet to: " + UDP_IP)
    sock.sendto(bytes(UDP_MSG, "utf-8"), (UDP_IP, UDP_PORT))

    time.sleep(1)