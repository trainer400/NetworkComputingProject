#!/bin/bash

# include helper.bash file: used to provide some common function across testing scripts
source "${BASH_SOURCE%/*}/../libs/helpers.bash"

# Read the YAML file into a variable
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
yaml=$(cat ${DIR}/config.yaml)

# Check if shyaml is installed, if not install it
if ! [ -x "$(command -v shyaml)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: shyaml is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing shyaml... ${COLOR_OFF}"
  sudo pip install shyaml
fi

# Read the load balancer virtual ip 
vip=$(echo "$yaml" | shyaml get-value vip)
num_ips=$(echo "$yaml" | shyaml get-length backends)
# Add the VIP to the number of total IPS
total_ips=$((1 + $num_ips))

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth $1
}
trap 'cleanup "$total_ips"' ERR

# The function parses the IP and sets the gateway to a 254 at the end of the address. It supposes /24 subnet
function config_gtw {
  # Set the separator to character .
  IFS='.'

  # Create the final IP string
  fIP=""

  # Split the IP and position in discarding the last byte
  read -ra ip <<< "$1"
  fIP="${ip[0]}.${ip[1]}.${ip[2]}.254"

  # Reset the separation character
  IFS=','

  # Config the gateway
  sudo ifconfig veth${2} ${fIP}/24 up

  # Store the computed GW in a global variable
  result=$fIP
}

# Enable verbose output
set -x

# Delete all previous veths + the virtual ip one
cleanup ${total_ips}
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Create a network namespace and a veth pair for every needed ip
create_veth ${total_ips}

# Configure the VIP
sudo ip netns exec ns1 ifconfig veth1_ ${vip}/24
config_gtw ${vip} '1'
sudo ip netns exec ns1 ip link set veth1_ up
vip_gw=$result

# Set the gateway as default routing gate
sudo ip netns exec ns1 ip route add default via ${vip_gw}

# Update the ARP table for virtual address
lb_mac=$(sudo ip netns exec ns1 ifconfig veth1_ | grep ether | awk '{print $2}')
sudo arp -s ${vip} $lb_mac

for (( i=2; i<=$total_ips;i++ )); do

  # Gather the server ip
  index=$(($i - 2))
  elem=$(echo "$yaml" | shyaml get-value backends.$index)
  server_ip=$(echo "$elem" | shyaml get-value "ip")

  # Config the gateway
  sudo ip netns exec ns${i} ifconfig veth${i}_ ${server_ip}/24 
  config_gtw ${server_ip} ${i}

  # Add the routing entry from VIP to the current IP
  gw=$result
  sudo ip netns exec ns${i} ip route add default via ${gw}
  sudo ip netns exec ns${i} ip link set veth${i}_ up

  mac=$(sudo ip netns exec ns1 ifconfig veth1_ | grep ether | awk '{print $2}')
  sudo arp -s ${gw} $mac -i veth1
done

# Accept and forward packets at the VIP gateway that use the gateway IP
sysctl -w net.ipv4.conf.veth1.accept_local=1

# Exec the XDP_LOADER program into the VIP gateway to enable XDP_TX
sudo ./xdp_loader -i veth1