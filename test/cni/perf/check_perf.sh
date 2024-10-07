#!/bin/bash

set -e

#
# $1: FQDN where the service is
#

N_WORKERS=${N_WORKERS:-4}

TOTAL_THROUGHPUT=0
LB_IP=${1:-$(minikube kubectl -- get service my-loadbalancer-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}')}

CMD=iperf
if [[ "${NETNS}" != "" ]]; then
	CMD="sudo ip netns exec ${NETNS} iperf -f m"
fi

# $1: worker
get_throughput(){
	INTERVALS=$(cat .worker_${1}.txt | grep -vi interval | grep -vi port | grep -iv '\-\-\-\-\-\-' | grep -iv window)
	THROUGHPUT=$(echo ${INTERVALS} | awk '{print $7}')

	TOTAL_THROUGHPUT=$(awk "BEGIN {print $TOTAL_THROUGHPUT + $THROUGHPUT}")
}

# $1: FQDN
# $2: port
check_perf(){
	echo "[port: $2] Starting N_WORKERS=${N_WORKERS}"
	for i in $(seq 1 $N_WORKERS); do
		(${CMD} -c ${1} -p ${2} 2>&1 > .worker_${i}.txt ) &
	done
	echo "[port: $2] All workers launched"
	wait
	for i in $(seq 1 $N_WORKERS); do
		get_throughput ${i}
	done
	rm .worker_*.txt
	AVG_THROUGHPUT=$(awk "BEGIN {print $TOTAL_THROUGHPUT/$N_WORKERS}")
	echo "[port: $2] Total throughput: ${TOTAL_THROUGHPUT}"
	echo "[port: $2] Average throughput per worker: ${AVG_THROUGHPUT}"
}

#Port 80
check_perf ${LB_IP} 80

#Port 8080
check_perf ${LB_IP} 8080
