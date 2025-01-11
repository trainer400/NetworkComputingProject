#!/bin/sh
# Stop avahi-daemon
sudo systemctl stop avahi-daemon
make && ./create-topo.sh && sudo ip netns exec ns1 ./l4_lb -i veth1_