#!/bin/bash

set -e
set -x

N_ATTEMPTS=5
RETRY_DELAY=5
PROG=tc_$1.o

#Compile eBPF programs
compile(){
	cd /opt/sfunnel
	make compile
}

#$1: PROG
#$2: IFACE
load_prog(){
	tc qdisc add dev $2 clsact
	tc filter add dev $2 ingress bpf da obj /opt/sfunnel/$1 sec funnel verbose
}

#$1: ACTION funnel/unfunnel
if [[ "$1" != "funnel" && "$1" != "unfunnel" ]]; then
	echo "Unknown action $1"
	exit 1;
fi

#Compile for this specific kernel
#compile

#Show
ls -la /opt/sfunnel

#Load
for IFACE in $(ls /sys/class/net); do
	for ((i=1; i<=$N_ATTEMPTS; i++)); do
		echo "Attaching BPF program '$PROG' to '$IFACE' using clsact qdisc..."
		load_prog $PROG $IFACE && break
		echo "WARNING: attempt $i failed on iface '$IFACE'. Retrying in $RETRY_DELAY seconds..."
		sleep 5
	done
	if [[ $i -ge $N_ATTEMPTS ]]; then
		echo "ERROR: unable to attach '$PROG' to '$IFACE'!"
		exit 1
	fi
done
