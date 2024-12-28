#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import socket
import random
from subprocess import Popen, PIPE
import re
import argparse

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP, Dot1Q

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

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-d", "--destination", required=True, type=str, help="The IP address of the destination")
    parser.add_argument("-p", "--packets", type=int, required=True, help="Number of packets to send")
    parser.add_argument("-m", "--message", type=str, required=True, help="Message to send")
    parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface over which the messages have to be sent")
    
    args = parser.parse_args()

    ip_addr = args.destination
    packets = args.packets
    message = args.message
    interface = args.interface

    addr = socket.gethostbyname(ip_addr)
    iface = get_if(interface)

    tos = 0

    ether_dst = get_dst_mac(addr)

    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    pkt = Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(dst=addr,tos=tos) /UDP(dport=123) /message

    for _ in range(packets):
        print("Sending on interface %s to %s" % (iface, str(addr)))
        sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()