#!/bin/sh
#
# Copyright (C) 2015 Evert Ramos <evert.ramosATgmailDOTcom>
#
# IPTABLES firewall configured to simplify the structure of the rules
#
# @version 2.0
#
# @hisotry
# 	1.0 - basic version
#	2.0 - added country IP blocking
# 
######################################################################
#
# Ports
#
# 1-1024	- Reserved Ports
# 1024-49152	- Registered Ports
# 49152-65535	- Private Ports
#
######################################################################
#
# 1. Configuration
#

# 1.1 Executable configuration
IPTABLES="/sbin/iptables"
BLOCK="/root/bin/firewall/block/block_ip.sh"
#BLOCK="/root/bin/firewall/geoip/block_country.sh"
#BLOCK="/root/bin/firewall/block/ip_list.sh"

# 1.2 Localhost Configuration
LO_IFACE="lo"
LO_IP="127.0.0.1"

source .env

# 1.3 Internet Configuration
INET_IP=$INET_IP
INET_IFACE="eth0"

#
# 2. Clear previous configuration
#
$IPTABLES -F
$IPTABLES -X

# 2.1 Read Special Rules

# 2.1.1 Block ips
$BLOCK

# Block country IP's - NOT IN USE...
#CLIST="cn kp kr vn"
#for c in $CLIST
#do
#	$BLOCK $c
#done

#
# 3. Proc set up
#

# 3.1 Required proc configuration
echo "1" > /proc/sys/net/ipv4/ip_forward

# 3.2 Non-Required proc configuration
#echo "1" > /proc/sys/net/ipv4/conf/all/rp_filter
#echo "1" > /proc/sys/net/ipv4/conf/all/proxy_arp
#echo "1" > /proc/sys/net/ipv4/ip_dynaddr

#
# 4. Rules set up
#

# 4.1 Filter table


# 4.1.1 Policies set
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

# 4.1.2 Create userspecified chains

# Create chain for bad tcp packets
$IPTABLES -N bad_tcp_packets

# Create separate chains for ICMP, TCP and UDP to traverse
$IPTABLES -N allowed
$IPTABLES -N tcp_packets
$IPTABLES -N udp_packets
$IPTABLES -N icmp_packets

# 4.1.3 Create content in userspecified chains

# bad_tcp_packets chain
$IPTABLES -A bad_tcp_packets -p tcp --tcp-flags SYN,ACK SYN,ACK \
-m state --state NEW -j REJECT --reject-with tcp-reset
$IPTABLES -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j LOG \
--log-prefix "No syn:"
$IPTABLES -A bad_tcp_packets -p tcp ! --syn -m state --state NEW -j DROP

# Allowing curl to access localhost by INET_IP
#$IPTABLES -A allowed -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
#$IPTABLES -A INPUT -s $INET_IP -m state --state ESTABLISHED,RELATED -j ACCEPT

# allowed chain
$IPTABLES -A allowed -p TCP --syn -j ACCEPT
$IPTABLES -A allowed -p TCP -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A allowed -p TCP -j DROP

# TCP rules
#$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 20 -j allowed
#$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 42021 -j allowed
#$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 21 -j allowed
#$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 22 -j allowed
# >> Porta substituta para ssh - inativo
$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 22 -j allowed
$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 80 -j allowed
$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 443 -j allowed
#$IPTABLES -A tcp_packets -p TCP -s 0/0 --dport 113 -j allowed

# Mysql para ip
#$IPTABLES -A tcp_packets -p TCP -s 191.176.114.228 --dport 3306 -j allowed
#$IPTABLES -A tcp_packets -p TCP -s 200.202.168.254 --dport 3306 -j allowed

#$IPTABLES -A INPUT -p tcp -s 200.202.168.254 --sport 1024:65535 -d $INET_IP --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A tcp_packets -p tcp -s 200.202.168.254 --sport 1024:65535 -d $INET_IP --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPTABLES -A tcp_packets -p tcp -s 191.176.114.228 --sport 1024:65535 -d $INET_IP --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT

# UDP ports
#$IPTABLES -A udp_packets -p UDP -s 0/0 --destination-port 53 -j ACCEPT
#$IPTABLES -A udp_packets -p UDP -s 0/0 --destination-port 123 -j ACCEPT
#$IPTABLES -A udp_packets -p UDP -s 0/0 --destination-port 2074 -j ACCEPT
#$IPTABLES -A udp_packets -p UDP -s 0/0 --destination-port 4000 -j ACCEPT

# In Microsoft Networks you will be swamped by broadcasts. 
# These lines will prevent them from showing up in the logs.
#$IPTABLES -A udp_packets -p UDP -i $INET_IFACE -d $INET_BROADCAST \
#--destination-port 135:139 -j DROP

# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
#$IPTABLES -A udp_packets -p UDP -i $INET_IFACE -d 255.255.255.255 \
#--destination-port 67:68 -j DROP

# ICMP rules
#$IPTABLES -A icmp_packets -p ICMP -s 0/0 -j DROP
$IPTABLES -A icmp_packets -p ICMP -s 0/0 --icmp-type 8 -j ACCEPT
$IPTABLES -A icmp_packets -p ICMP -s 0/0 --icmp-type 11 -j ACCEPT

# 4.1.4 INPUT chain

# Bad TCP packets we don't want.
$IPTABLES -A INPUT -p tcp -j bad_tcp_packets

# Rules for special networks not part of the Internet
$IPTABLES -A INPUT -p ALL -i $LO_IFACE -s $LO_IP -j ACCEPT
#$IPTABLES -A INPUT -p ALL -i $LO_IFACE -s $INET_IP -j ACCEPT
#$IPTABLES -A INPUT -m state --state ESTABLISHED -j ACCEPT

# Rules for incoming packets from the internet.
$IPTABLES -A INPUT -p ALL -d $INET_IP -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -p TCP -i $INET_IFACE -j tcp_packets
$IPTABLES -A INPUT -p UDP -i $INET_IFACE -j udp_packets
$IPTABLES -A INPUT -p ICMP -i $INET_IFACE -j icmp_packets

$IPTABLES -A INPUT -p ALL -s $INET_IP -j ACCEPT

# If you have a Microsoft Network on the outside of your firewall, you may
# also get flooded by Multicasts. We drop them so we do not get flooded by
# logs
#$IPTABLES -A INPUT -i $INET_IFACE -d 224.0.0.0/8 -j DROP

# Log weird packets that don't match the above.
#$IPTABLES -A INPUT -m limit --limit 3/minute --limit-burst 3 -j LOG \
#--log-level DEBUG --log-prefix "IPT INPUT packet died: "

# 4.1.5 FORWARD chain

# Bad TCP packets we don't want
$IPTABLES -A FORWARD -p tcp -j bad_tcp_packets

# Accept the packets we actually want to forward
$IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Log weird packets that don't match the above.
#$IPTABLES -A FORWARD -m limit --limit 3/minute --limit-burst 3 -j LOG \
#--log-level DEBUG --log-prefix "IPT FORWARD packet died: "

# 4.1.6 OUTPUT chain

# Bad TCP packets we don't want.
$IPTABLES -A OUTPUT -p tcp -j bad_tcp_packets

# SMPT OUTPUT rules
$IPTABLES -A OUTPUT -p tcp --sport 25 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 465 -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --sport 587 -j ACCEPT

# Mysql OUTPUT rules
#$IPTABLES -A OUTPUT -p tcp --sport 3306 -d 200.202.168.254 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
#$IPTABLES -A OUTPUT -p tcp --sport 3306 -d 191.176.114.228 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT
#$IPTABLES -A OUTPUT -p tcp -s $INET_IP --sport 3306 -d 200.202.168.254 --dport 1024:65535 -m state --state ESTABLISHED -j ACCEPT


# Special OUTPUT rules to decide which IP's to allow
$IPTABLES -A OUTPUT -p ALL -s $LO_IP -j ACCEPT
$IPTABLES -A OUTPUT -p ALL -s $INET_IP -j ACCEPT

# Log weird packets that don't match the above.
#$IPTABLES -A OUTPUT -m limit --limit 3/minute --limit-burst 3 -j LOG \
#--log-level DEBUG --log-prefix "IPT OUTPUT packet died: "


# 4.2 nat table

# 4.2.1 Policies set

# 4.2.2 Create user specified chains

# 4.2.3 Create content in user specified chains

# 4.2.4 PREROUTING chain

# Enable port 49685 to be nated to port 22
#$IPTABLES -t nat -A PREROUTING -p tcp --sport 46985 -j REDIRECT --to-ports 22

# 4.2.5 POSTROUTING chain

# Enable simple IP Forwarding and Network Address Translation
$IPTABLES -t nat -A POSTROUTING -o $INET_IFACE -j SNAT --to-source $INET_IP

# 4.2.6 OUTPUT chain


# 4.3 Mangle table

# 4.3.1 Set policies

# 4.3.2 Create user specified chains

# 4.3.3 Create content in user specified chains

# 4.3.4 PREROUTING chain

# 4.3.5 INPUT chain

# 4.3.6 FORWARD chain

# 4.3.7 OUTPUT chain

# 4.3.8 POSTROUTING chain



exit 0
