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

  # Split the IP
  count=0
  read -ra ip <<< "$1"
  for number in "${ip[@]}"; do
    count=$((1 + $count))

    # For every IP byte, if it is the fourth one (the last one) the it is changed with 254
    if [ $count -eq "4" ]
    then
      fIP="${fIP}.254"
    else
      if [ $count -eq "1" ]
      then
        fIP="$number"
      else
        fIP="${fIP}.${number}"
      fi
    fi
  done

  # Reset the separation character
  IFS=','

  # Config the gateway
  sudo ifconfig veth${2} ${fIP}/24 up
}

# Enable verbose output
set -x

# Delete all previous veths + the virtual ip one
cleanup ${total_ips}
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create a network namespace and a veth pair for every needed ip
create_veth ${total_ips}

# Configure the VIP
sudo ip netns exec ns1 ifconfig veth1_ ${vip}/24
config_gtw ${vip} '1'


for (( i=2; i<=$total_ips;i++ )); do

  # Gather the server ip
  index=$(($i - 2))
  elem=$(echo "$yaml" | shyaml get-value backends.$index)
  ip=$(echo "$elem" | shyaml get-value "ip")


  sudo ip netns exec ns${i} ifconfig veth${i}_ ${ip}/24 
  config_gtw "${ip}" ${i}
done
