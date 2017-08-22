#!/bin/bash
#
# Copyright (C)2015  Evert Ramos <evert.ramosATgmailDOTcom>
#
##############################################################
#
# Set rule to DROP or ACCEPT the IP list
#
##############################################################

# 1. Local configuration

# 1.1 iptables path
IPTABLES="/sbin/iptables"

# 1.2 Get the file name
FILENAME="/root/bin/firewall/block/ip/ip_list"
#FILENAME=$(pwd)"/block/ip/ip_list"

# 2. Block the country IP's
while read -r line
do
    IP=$line
    $IPTABLES -A INPUT -s $IP -j DROP
    echo $IP " blocked"
done < $FILENAME

exit
