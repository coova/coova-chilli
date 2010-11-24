#!/bin/sh
TUNTAP=$(basename $DEV)
. /etc/chilli/functions

brctl delif br0 ath0

if [ "$HS_BRIDGE" = "on" ]; then
    brctl addif br0 $TUNTAP
else
    iptables -t nat -I POSTROUTING -o br0 -j MASQUERADE 
fi