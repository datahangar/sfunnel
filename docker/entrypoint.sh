#!/bin/bash

set -e
set -x

#Compile eBPF programs
compile(){
	cd /opt/sfunnel
	make compile
}

#$1: ACTION funnel/unfunnel
if [[ "$1" != "funnel" && "$1" != "unfunnel" ]]; then
	echo "Unknown action $1"
	exit 1;
fi

PROG=tc_$1.o

#Compile for this specific kernel
#compile
ls -la /opt/sfunnel

#Attach
for IFACE in $(ls /sys/class/net); do
	tc qdisc add dev $IFACE clsact
	tc filter add dev $IFACE ingress bpf da obj /opt/sfunnel/$PROG sec funnel verbose
done
