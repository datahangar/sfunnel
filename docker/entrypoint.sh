#!/bin/bash

set -e
#set -x

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
	echo "[INFO] SFUNNEL_RULESET='$SFUNNEL_RULESET'"
	echo $SFUNNEL_RULESET > /opt/sfunnel/src/ruleset
fi

#Compile sfunnel only if new ruleset is specified
if test -f /opt/sfunnel/src/ruleset; then
	echo "[INFO] Compiling sfunnel with custom ruleset..."
	echo "==="
	cat /opt/sfunnel/src/ruleset
	echo "==="
	compile
else
	echo "[INFO] Using default ruleset..."
	echo "==="
	cat /opt/sfunnel/src/ruleset.default
	echo "==="
fi

#Load
IFACES=$(ls /sys/class/net | tr "\n" " " | sed 's/\s*$//g')

echo ""
echo -e "[INFO] Attaching BPF program '$PROG' to IFACES={$IFACES} using clsact qdisc...\n"
for IFACE in $IFACES; do
	for ((i=1; i<=$N_ATTEMPTS; i++)); do
		echo "[INFO] Attaching BPF program to '$IFACE'..."
		load_prog $PROG $IFACE && break
		echo "[WARNING] attempt $i failed on iface '$IFACE'. Retrying in $RETRY_DELAY seconds..."
		sleep 5
	done
	if [[ $i -ge $N_ATTEMPTS ]]; then
		echo "[ERROR] unable to attach BPF program to '$IFACE'!"
		exit 1
	fi
	echo -e "[INFO] Successfully attached BPF program to '$IFACE'.\n"
done
echo "[INFO] Successfully attached '$PROG' to interfaces {$IFACES}"
