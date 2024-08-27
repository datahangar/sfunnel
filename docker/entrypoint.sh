#!/bin/bash

set -e
set -x

N_ATTEMPTS=5
RETRY_DELAY=5
PROG=/opt/sfunnel/src/tc_sfunnel.o

#Compile eBPF program only if rulesset are defined at load time
#either via file or ENV
compile(){
	cd /opt/sfunnel/src
	make
}

#$1: PROG
#$2: IFACE
load_prog(){
	tc qdisc add dev $2 clsact
	tc filter add dev $2 ingress bpf da obj $1 sec funnel verbose
}

###

#If SFUNNEL_RULESET is defined, create the file
if [[ "$SFUNNEL_RULESET" != "" ]]; then
	echo "[NOTICE] SFUNNEL_RULESET='$SFUNNEL_RULESET'"
	echo $SFUNNEL_RULESET > /opt/sfunnel/src/ruleset
fi

#Compile sfunnel only if new ruleset is specified
if test -f /opt/sfunnel/src/ruleset; then
	echo "[NOTICE] Compiling sfunnel with custom ruleset..."
	echo "==="
	cat /opt/sfunnel/src/ruleset
	echo "==="
	compile
else
	echo "[NOTICE] Using default ruleset..."
	echo "==="
	cat /opt/sfunnel/src/ruleset.default
	echo "==="
fi

#Show
ls /opt/sfunnel
ls /opt/sfunnel/src

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
