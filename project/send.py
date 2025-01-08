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

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP, Dot1Q

class ServerStats:
    flows = 0
    packets = 0
    to_send_packets = 0

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

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-y", "--yaml", required=False, type=str,default="config.yaml", help="The yaml configuration file [default: config.yaml]")
    parser.add_argument("-f", "--flows", type=int, required=True, help="Number of flows to generate")
    args = parser.parse_args()

    # Get the passed arguments
    yaml_file = args.yaml
    flows = args.flows

    # Load the configuration yaml file
    with open(yaml_file, "r") as file:
        yaml_content = yaml.safe_load(file)
    
    # Load the configuration from the yaml file
    vip = yaml_content["vip"]
    backend_number = len(yaml_content["backends"])

    # Track the server_stats stats
    stats = [ServerStats() for s in range(backend_number)]

    # For each new flow, send an arbitrary number of packets from 5 to 10000
    for _ in range(flows):
        # Determinant in discriminating the flows
        src_port = _ + 8000

        # Number of packet per flow
        num_packet = random.randint(5, 300)

        # Find the estimated best server
        best = find_best_server(stats)

        # Update the stats
        stats[best].flows += 1
        stats[best].packets += num_packet
        stats[best].to_send_packets = num_packet

        print(f"Flow {_}, sending {num_packet} packets -> {best}")

        for n in range(num_packet):
            send_packet(vip, src_port, "Test")


if __name__ == '__main__':
    main()