#!/bin/sh
#
# Copyright (C) 2015 Evert Ramos <evert.ramosATgmailDOTcom>
#
######################################################################
#
# Ports
#
# 1-1024    - Reserved Ports
# 1024-49152    - Registered Ports
# 49152-65535   - Private Ports
#
######################################################################
#
# 1. Configuration
#

# 1.1 IPTables Configuration
IPTABLES="/sbin/ip6tables"

# 1.2 Localhost Configuration
LO_IFACE="lo"
LO_IP="::1"

source .env

# 1.3 Internet Configuration
INET_IP=$INET_IPV6
INET_IFACE="eth0"

#
# 2. Clear previous configuration
#
$IPTABLES -F
$IPTABLES -X

#
# 3. Rules set up
#

# 3.1 Policies set
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

# 3.2 Accept loopback traffic
#$IPTABLES -A INPUT -i $LO_IFACE -j ACCEPT
#$IPTABLES -A OUTPUT -o $LO_IFACE -j ACCEPT

# 3.3 Block/Allow PING
$IPTABLES -A INPUT -p icmpv6 --icmpv6-type 128 -j DROP

# 3.4 Block/Allow all icmpv6 traffice
#$IPTABLES -A INPUT -p icmpv6 -j DROP

# 3.5 Personal rules
#$IPTABLES -A INPUT -p tcp -s 0/0 --destination-port 80 -j ACCEPT

# DNS
#$IPTABLES -A INPUT -p udp -m udp --dport 53 -j ACCEPT
#$IPTABLES -A INPUT -m state --state NEW -m tcp -p tcp --dport 53 -j ACCEPT
#$IPTABLES -A INPUT -m state --state NEW -m udp -p udp --dport 53 -j ACCEPT

# 3.6 Block unwanted traffice
$IPTABLES -A INPUT -j DROP
$IPTABLES -A OUTPUT -j DROP
$IPTABLES -A FORWARD -j DROP

exit 0
