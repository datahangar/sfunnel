#!/bin/bash

set -e

#
# Check affinity between port 80 and 8080
#
# $1: LB_IP or FQDN
#
# Env:
# $ITERATIONS: number of iterations (~1sec per iteration)
# $SRC_IPS: check affinity from (e.g. "192.168.254.2 192.168.254.3")

if [[ "${DEBUG}" != "" ]]; then
	set -x
fi

ITERATIONS=${ITERATIONS:-1}
LB_IP=${1:-$(minikube kubectl -- get service my-loadbalancer-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')}

#$1: URL
#$2: SRC_IP
get_pod(){
	CURL_OPTS=""
	if [[ "${2}" != "" ]]; then
		CURL_OPTS=" --interface ${2}"
	fi
	sudo ip netns exec client curl ${CURL_OPTS} -s ${1} | sed 's/^.*by\s*//'
}

#$1: SRC_IP or ""
check_affinity(){
	HTTP=$(get_pod ${LB_IP}:80 ${1})
	ALT_HTTP=$(get_pod ${LB_IP}:8080 ${1})
	if [[ "${HTTP}" != "${ALT_HTTP}" ]]; then
		echo "ERROR: affinity NOT respected"
		echo "HTTP: ${HTTP}"
		echo "ALT_HTTP: ${ALT_HTTP}"
		exit 1
	fi

	echo "Serving pod: "
	echo "  HTTP:     ${HTTP}"
	echo "  ALT_HTTP: ${ALT_HTTP}"
}

#Wait for nginx to be operative
echo "Waiting for ${LB_IP}:80 to return a valid HTTP response..."
while $( [[ "$(get_pod ${LB_IP}:80 | grep my-nginx-deployment)" == "" ]] ); do
	sleep 1
done
sudo ip netns exec client curl -s ${LB_IP}:80

#Make sure service at 8080 is also reachable (no misconfigs)
echo "Waiting for ${LB_IP}:8080 to return a valid HTTP response..."
while $( [[ "$(get_pod ${LB_IP}:8080 | grep my-nginx-deployment)" == "" ]] ); do
	sleep 1
done
sudo ip netns exec client curl -s ${LB_IP}:8080

#Check affinity
i=1
while true; do
	echo "Iteration ${i}/${ITERATIONS}..."
	if [[ "${SRC_IPS}" == "" ]]; then
		check_affinity
	else
		for IP in ${SRC_IPS}; do
			echo "Checking port affinity to ${LB_IP} from ${IP}..."
			check_affinity ${IP}
		done
	fi

	if [[ $i -eq ${ITERATIONS} ]]; then
		break
	fi
	((i++))

	sleep 1;
	echo ""
done

echo "OK"
