#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import socket
import random
from subprocess import Popen, PIPE
import re
import argparse
import yaml
import time
import logging

from scapy.all import AsyncSniffer, sendp, get_if_list, Ether, get_if_hwaddr, IP, UDP

logger = logging.getLogger(__name__)

class FlowStats:
    packets = 0
    assigned_server = -1

class ServerStats:
    def __init__(self, iface):
        self.iface = iface

    flows = 0
    packets = 0
    iface = ""

# Custom formatter for logging purposes (colored levelname and integer unix timestamp)
class CustomFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[91m',    # Red
        'INFO': '\033[92m',     # Green
    }
    RESET = '\033[0m'  # Reset color

    def format(self, record):
        # Truncate the timestamp to integer
        record.unix_time = int(record.created)

        # Change color between DEBUG and INFO
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{self.RESET}"
        return super().format(record)

def configure_logger(verbose: bool):
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Create a handler that outputs logs to stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Define a logging format
    formatter = CustomFormatter('[%(unix_time)s][%(levelname)s] %(message)s')
    handler.setFormatter(formatter)

    # Add the handler to the logger
    logger.addHandler(handler)

def get_if(interface : str):
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if interface in i:
            iface=i
            break
    if not iface:
        print("Cannot find " + interface + " interface")
        exit(1)
    return iface

def get_dst_mac(ip):

    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = str(pid.communicate()[0])
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def score(server: ServerStats) -> int: 
    return 0 if server.flows == 0 else int(server.packets / server.flows)

def find_best_server(servers: list[ServerStats]):
    best_index = 0
    best_score = score(servers[0])
    for s in range(len(servers)):
        current_score = score(servers[s])

        if current_score < best_score:
            best_index = s
            best_score = current_score
    
    return best_index

def send_packet(vip: str, src_port: int, message: str):
    addr = socket.gethostbyname(vip)
    iface = get_if("veth1")
    tos = 0
    ether_dst = get_dst_mac(addr)

    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    # Setup the packet
    pkt = Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(dst=addr,tos=tos) /UDP(sport=src_port, dport=8000) /message
    sendp(pkt, iface=iface, verbose=False)

def send_packets(rcv_iface: str, num_packet: int, vip: str, src_port: int):
    # Create the sniffer to check the the received packets are correct in number and type
    f = AsyncSniffer(filter="proto 4", iface = rcv_iface)
    f.start()

    # Wait the sniffing process to start (for some reason f.running is not enough)
    while not (hasattr(f, 'stop_cb') and f.running):
        time.sleep(0.01)  # Poll every 10ms

    # Send the determined number of packets
    for n in range(num_packet):
        send_packet(vip, src_port, "Test")

    # Stop the sniffer
    f.stop()

    return f.results

def check_packet(pkt) -> bool:
    # Check IP checksum
    if not pkt.haslayer(IP):
        logger.debug("Packet has not an IP layer!")
        return False
    
    # Get checksum
    ip_hdr = pkt[IP]
    checksum = ip_hdr.chksum

    # Remove the checksum and recompute the packet
    del ip_hdr.chksum
    ip_hdr = ip_hdr.__class__(bytes(ip_hdr))

    # Compare checksum
    if checksum != ip_hdr.chksum:
        logger.debug(f"Incorrect IP checksum {checksum} != {ip_hdr.chksum}!")
        return False

    # Check if UDP is coherent
    if not pkt.haslayer(UDP):
        logger.debug("Packet has not a UDP layer!")
        return False
    
    # Check the test message
    msg = bytes(pkt[UDP].payload).decode('utf-8', errors='ignore')
    if msg != "Test":
        logger.debug("Packet does not contain the 'Test' message")
        return False
    
    return True

def print_stats(stats : list[ServerStats]):
    logger.info("Backend Server Stats:")
    
    for i in range(len(stats)):
        # Compute the final load and print stats
        logger.info(f"ServerID: {i}, Iface: {stats[i].iface}, Pkts: {stats[i].packets}, Flows: {stats[i].flows}, Load: {score(stats[i])}")

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-y", "--yaml", required=False, type=str,default="config.yaml", help="The yaml configuration file [default: config.yaml]")
    parser.add_argument("-f", "--flows", type=int, required=True, help="Number of flows to generate")
    parser.add_argument("-p", "--packets", type=int, required=False, default=10000, help="Number of maximum packets to send per flow")
    parser.add_argument("-v", "--verbose", action="store_true", required=False, default=False, help="Output verbose when an error occurrs")
    args = parser.parse_args()

    # Get the passed arguments
    yaml_file = args.yaml
    num_flows = args.flows
    max_packets = args.packets

    # Set logging level
    configure_logger(args.verbose)

    # Load the configuration yaml file
    with open(yaml_file, "r") as file:
        yaml_content = yaml.safe_load(file)
    
    # Load the configuration from the yaml file
    vip = yaml_content["vip"]
    backend_number = len(yaml_content["backends"])

    # Track the server_stats stats
    stats = [ServerStats("veth" + str(s + 2)) for s in range(backend_number)]
    flows = [FlowStats() for f in range(num_flows)]

    logger.debug("Starting Packet send!")

    # For each new flow, send an arbitrary number of packets from 5 to 10000
    while True:
        # Select a random flow
        f = random.randint(0, num_flows-1)

        # Determinant in discriminating the flows
        src_port = f + 8000

        # Send packets only if the flow is not saturated
        if not(flows[f].packets < max_packets and max_packets-flows[f].packets > 5):
            break

        # Number of packet per flow
        num_packet = random.randint(5, min(100, max_packets-flows[f].packets))
        
        # Find the estimated best server if not already assigned
        new_server = flows[f].assigned_server == -1
        best = find_best_server(stats) if new_server else flows[f].assigned_server
        flows[f].assigned_server = best
        flows[f].packets += num_packet
        stats[best].flows += 1 if new_server else 0
        stats[best].packets += num_packet

        # Send all the packets
        logger.info(f"Flow {f}, sending {num_packet} packets [{flows[f].packets}] -> {best}:{stats[best].iface}")
        results = send_packets(stats[best].iface, num_packet, vip, src_port)

        # Check the number of packets
        if num_packet != len(results):
            logger.debug(f"Did not receive the correct amount of packets {num_packet} != {len(results)}")
            break
        
        # Check the packets integrity
        integrity = True
        for pkt in results:
            integrity = integrity and check_packet(pkt)
        
        if not integrity:
            logger.debug("Found corrupted packet!")
            break

    logger.debug("Simulation terminated!")
    print_stats(stats)


if __name__ == '__main__':
    main()