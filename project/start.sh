#!/bin/sh
make && ./create-topo.sh && sudo ip netns exec ns1 ./l4_lb -i veth1_