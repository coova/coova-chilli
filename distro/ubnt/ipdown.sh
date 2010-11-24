#!/bin/sh
TUNTAP=$(basename $DEV)
# brctl addif br0 ath0
iptables -t nat -D POSTROUTING -o br0 -j MASQUERADE 2>/dev/null
brctrl delif br0 $TUNTAP 2>/dev/null