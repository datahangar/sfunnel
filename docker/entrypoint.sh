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
SEG_DEV_NAME=${SEG_DEV_NAME:-_seg}
_IFACES=$(ls /sys/class/net | grep -v "^${SEG_DEV_NAME}" | tr "\n" " " | sed 's/\s*$//g')
IFACES=${IFACES:-$_IFACES}
NETNS=${NETNS:-}


SRC_DIR=/opt/sfunnel/src
PROG_DIR=/opt/sfunnel/bin
PROG_INGRESS=${PROG_DIR}/tc_sfunnel_ingress.o
PROG_EGRESS=${PROG_DIR}/tc_sfunnel_egress.o

#Compile eBPF programs (INGRESS/EGRESS)
compile(){
	cd ${SRC_DIR}
	mkdir -p ${PROG_DIR}

	for INGRESS in 0 1; do
		INGRESS=${INGRESS} SEG_DEV_IFINDEX=${SEG_DEV_IFINDEX} SEG_PAIR_DEV_IFINDEX=${SEG_PAIR_DEV_IFINDEX} SEG_PAIR_DEV_MAC="${SEG_PAIR_DEV_MAC}" DEBUG=${DEBUG} FILE=/etc/sfunnel/ruleset make
		if [ "$INGRESS" -eq 1 ]; then
			mv ${SRC_DIR}/tc_sfunnel.o ${PROG_INGRESS}
		else
			mv ${SRC_DIR}/tc_sfunnel.o ${PROG_EGRESS}
		fi
	done
}

#$1: IFACE
#$2: direction {ingress, egress}
load_prog(){
	PROG=$( [[ ${2} == "ingress" ]] && echo ${PROG_INGRESS} || echo ${PROG_EGRESS} )
	for ((i=1; i<${N_ATTEMPTS}; i++)); do
		echo "[INFO] Attaching BPF program '${PROG}' to '${1}' direction '${2}'..."
		tc filter add dev ${1} ${2} bpf da obj ${PROG} verbose
		if [[ "$?" == "1" ]]; then
			echo "[WARNING] attempt ${i} failed on iface '${1}', direction '${2}', prog '${PROG}'. Retrying in ${RETRY_DELAY} seconds..."
			sleep ${RETRY_DELAY}
		else
			break;
		fi
	done

	if [[ ${i} -ge ${N_ATTEMPTS} ]]; then
		echo "[ERROR] unable to attach BPF program to '${1}'!"
		exit 1
	fi

	echo ""
}

#$1: IFACE
#$2: direction {ingress, egress}
clean_prog(){
	tc filter show dev ${1} ${2}
	tc filter del dev ${1} ${2}
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
echo "  \$SEG_DEV_NAME='${SEG_DEV_NAME}'"
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

# Create GSO/TSO/UFO unsegmenting device (work-around)
if [[ "${SEG_DEV_NAME}" != "" ]]; then
	if [[ "$(ip link | grep ${SEG_DEV_NAME})" == "" ]]; then
		ip link add ${SEG_DEV_NAME} type veth peer name ${SEG_DEV_NAME}_pair
	fi
	ip link set up dev ${SEG_DEV_NAME}
	ip link set up dev ${SEG_DEV_NAME}_pair
	ethtool -K ${SEG_DEV_NAME} gso off tso off ufo off
	ethtool -K ${SEG_DEV_NAME}_pair gso off tso off ufo off
	SEG_DEV_IFINDEX=$(ip link show ${SEG_DEV_NAME} | head -n 1 | awk '{print $1}' | tr -d ':')
	SEG_PAIR_DEV_IFINDEX=$(ip link show ${SEG_DEV_NAME}_pair | head -n 1 | awk '{print $1}' | tr -d ':')
	SEG_PAIR_DEV_MAC="$(ip -j link show ${SEG_DEV_NAME}_pair | jq -r '.[0].address' | tr -d ':' | sed 's/\(..\)/0x\1, /g' | sed 's/,\s*$$//')"

	sysctl -q net.ipv4.conf.${SEG_DEV_NAME}.rp_filter=0
	sysctl -q net.ipv4.conf.${SEG_DEV_NAME}.accept_local=1
	sysctl -q net.ipv4.conf.${SEG_DEV_NAME}_pair.rp_filter=0
	sysctl -q net.ipv4.conf.${SEG_DEV_NAME}_pair.accept_local=1
	sysctl -q net.ipv4.ip_forward=1
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
	echo -e "[INFO] Attaching BPF program on IFACES={$IFACES} DIRECTION=${DIRECTION} using clsact qdisc...\n"
fi

for IFACE in ${IFACES}; do
	if [[ "${CLEAN}" != "1" ]]; then
		#Create clsact qdisc once; allow to reuse existing one
		tc qdisc add dev ${IFACE} clsact || echo "[WARNING] unable to create clsact; already present?"
	fi

	if [[ ${DIRECTION} != "egress" ]]; then
		${OP} ${IFACE} ingress
	fi
	if [[ ${DIRECTION} != "ingress" ]]; then
		${OP} ${IFACE} egress
	fi

	echo -e "[INFO] Successfully ${OP_STR}ed BPF program(s) on '${IFACE}' DIRECTION=${DIRECTION}.\n"
done

if [[ "${SEG_DEV_NAME}" != "" ]]; then
	# Attach program to segmenting device (work-around)
	# When segmenting GSO functionality the program is split between:
	#
	# Ingress:
	#  - INGRESS IFACE: lookup, redirect to ${SEG_DEV_NAME}
	#  - ${SEG_DEV_NAME}: GSO segmentation
	#  - ${SEG_DEV_NAME}_pair: rule actions (cached)
	#
	# Egress:
	#  - EGRESS IFACE: lookup, redirect to ${SEG_DEV_NAME}
	#  - ${SEG_DEV_NAME}: GSO segmentation
	#  - ${SEG_DEV_NAME}_pair: NOP (hairpin routing hop)
	#  - EGRESS IFACE (second pass): rule actions (cached)

	if [[ "${CLEAN}" != "1" ]]; then
		#Create clsact qdisc once; allow to reuse existing one
		tc qdisc add dev ${SEG_DEV_NAME}_pair clsact || echo "[WARNING] unable to create clsact; already present?"
	fi

	if [[ ${DIRECTION} != "egress" ]]; then
		${OP} ${SEG_DEV_NAME}_pair ingress
	fi
fi

echo "[INFO] Successfully ${OP_STR}ed BPF program(s) on interfaces {${IFACES}} DIRECTION=${DIRECTION}"
