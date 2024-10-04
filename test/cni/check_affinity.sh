#!/bin/bash

#
# Check affinity between port 80 and 8080
#
# $1: test time in seconds
#

#$1: URL
get_pod(){
	sudo ip netns exec client curl -s ${1} | sed 's/^.*by\s*//'
}


LB_IP="$(minikube kubectl -- get service my-loadbalancer-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"

#Wait for nginx to be operative
while $( [[ "$(get_pod ${LB_IP}:80 | grep my-nginx-deployment)" == "" ]] ); do
	sleep 1

done

i=0
while true; do
	HTTP=$(get_pod ${LB_IP}:80)
	ALT_HTTP=$(get_pod ${LB_IP}:8080)
	if [[ "${HTTP}" != "${ALT_HTTP}" ]]; then
		echo "ERROR: affinity NOT respected"
		echo "HTTP: ${HTTP}"
		echo "ALT_HTTP: ${ALT_HTTP}"
		exit 1
	fi

	((i++))
	if [[ $i -eq ${1} ]]; then
		break
	fi

	sleep 1;
done

echo "OK"
