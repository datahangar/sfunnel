#!/bin/bash

set -e

#First thing, invoke itself into the right NETNS
if [[ ${NETNS} != "" ]]; then
	if [[ ${_NETNS} == "" ]]; then
		echo "Entering netns='${NETNS}'..."
		export _NETNS="${NETNS}"
		env | awk -F'=' '{print $1"=\"" $2"\""}' > .env
		if [[ "${DEBUG}" == "1" ]]; then
			cat .env
		fi
		ip netns exec ${NETNS} bash -c "${0} ${@}"
		exit $?
	else
		echo "In netns='${NETNS}'..."
		source .env
		if [[ "${DEBUG}" == "1" ]]; then
			env
		fi
	fi
fi

#Env variables
DEBUG=${DEBUG:-0}
CLEAN=${CLEAN:-0}

N_ATTEMPTS=${N_ATTEMPTS:-6}
RETRY_DELAY=${RETRY_DELAY:-3}

DIRECTION=${DIRECTION:-ingress}
_IFACES=$(ls /sys/class/net | tr "\n" " " | sed 's/\s*$//g')
IFACES=${IFACES:-$_IFACES}
NETNS=${NETNS:-}

PROG=/opt/sfunnel/src/tc_sfunnel.o

#Compile eBPF program only if rulesset are defined at load time
#either via file or ENV
compile(){
	cd /opt/sfunnel/src
	DEBUG=${DEBUG} FILE=/etc/sfunnel/ruleset make
}

#$1: PROG
#$2: IFACE
#$3: direction {ingress, egress}
load_prog(){
	for ((i=1; i<${N_ATTEMPTS}; i++)); do
		echo "[INFO] Attaching BPF program '${1}' to '${2}' direction '${3}'..."
		tc filter add dev ${2} ${3} bpf da obj ${1} sec funnel verbose
		if [[ "$?" == "1" ]]; then
			echo "[WARNING] attempt ${i} failed on iface '${2}', direction '${3}', prog '${1}'. Retrying in ${RETRY_DELAY} seconds..."
			sleep ${RETRY_DELAY}
		else
			break;
		fi
	done

	if [[ ${i} -ge ${N_ATTEMPTS} ]]; then
		echo "[ERROR] unable to attach BPF program to '${2}'!"
		exit 1
	fi

	echo ""
}

#$1: PROG
#$2: IFACE
#$3: direction {ingress, egress}
clean_prog(){
	tc filter show dev ${2} ${3}
	tc filter del dev ${2} ${3}
}

# Check direction is valid
case "${DIRECTION}" in
	ingress | egress | both)
	;;
	*)
	echo "FATAL: Invalid traffic direction '${DIRECTION}'. Allowed values {ingress, egress, both}."
	exit 1
	;;
esac

# Splash and useful info
echo "[INFO] sfunnel $(cat /opt/sfunnel/VERSION)"
echo "[INFO] ENVs:"
echo "  \$SFUNNEL_RULESET='${SFUNNEL_RULESET}'"
echo "  \$IFACES='${IFACES}'"
echo "  \$DIRECTION='${DIRECTION}'"
echo "  \$DEBUG='${DEBUG}'"
echo "  \$NETNS='${NETNS}'"
echo "  \$N_ATTEMPTS='${N_ATTEMPTS}'"
echo "  \$RETRY_DELAY='${RETRY_DELAY}'"
echo "[INFO] Container info:"
echo "  Kernel: $(uname -a)"
echo "  Debian: $(cat /etc/debian_version)"
echo "  python3: $(python3 --version)"
echo "  clang: $(clang --version)"
echo "  iproute2: $(ip -V)"

# Enable full debug
if [[ "${DEBUG}" == "1" ]]; then
	set -x
fi

#Make sure /etc/sfunnel exists, even if no volume is mounted
mkdir -p /etc/sfunnel

if [[ "${CLEAN}" == "1" ]]; then
	OP=clean_prog
	OP_STR=clean
	echo -e "[INFO] Cleaning ALL BPF programs on IFACES={$IFACES} DIRECTION=${DIRECTION} using clsact qdisc...\n"
else
	#Check that a ruleset has been defined
	if [[ "${SFUNNEL_RULESET}" == "" && ! -f /etc/sfunnel/ruleset ]]; then
		echo "[ERROR] Neither '\$SFUNNEL_RULESET' is defined nor '/etc/sfunnel/ruleset' present. Aborting..."
		exit 1
	fi

	#If SFUNNEL_RULESET is defined, create/overwrite the file
	if [[ "${SFUNNEL_RULESET}" != "" ]]; then
		echo "[INFO] SFUNNEL_RULESET='${SFUNNEL_RULESET}'"
		echo ${SFUNNEL_RULESET} > /etc/sfunnel/ruleset
	fi

	#Compile sfunnel with the ruleset
	echo "[INFO] Recompiling sfunnel BPF program with ruleset:"
	echo "==="
	cat /etc/sfunnel/ruleset
	echo "==="
	compile

	OP=load_prog
	OP_STR=attach
	echo -e "[INFO] Attaching BPF program '${PROG}' on IFACES={$IFACES} DIRECTION=${DIRECTION} using clsact qdisc...\n"
fi

for IFACE in ${IFACES}; do
	if [[ "${CLEAN}" != "1" ]]; then
		#Create clsact qdisc once; allow to reuse existing one
		tc qdisc add dev ${IFACE} clsact || echo "[WARNING] unable to create clsact; already present?"
	fi

	if [[ ${DIRECTION} != "egress" ]]; then
		${OP} ${PROG} ${IFACE} ingress
	fi
	if [[ ${DIRECTION} != "ingress" ]]; then
		${OP} ${PROG} ${IFACE} egress
	fi

	echo -e "[INFO] Successfully ${OP_STR}ed BPF program(s) on '${IFACE}' DIRECTION=${DIRECTION}.\n"
done

echo "[INFO] Successfully ${OP_STR}ed BPF program(s) on interfaces {${IFACES}} DIRECTION=${DIRECTION}"
