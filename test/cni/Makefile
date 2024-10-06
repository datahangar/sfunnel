.PHONY: all check

SHELL=/bin/bash

CPUS ?= 4
NODES ?= 1

ifeq ($(DEBUG),1)
    DEBUG := 1
else
    DEBUG := 0
endif

ifeq ($(VERBOSE),1)
    QUIET :=
else
    QUIET := @
endif

CNI ?= cilium
ifeq ($(CNI),cilium-kpr)
    override CNI := cilium
    CILIUM_KPR := 1
endif

CLANG ?= clang

ITERATIONS ?= 10
RULESET_EGRESS := "ip tcp dport 8080 actions funnel tcp dport 80 sport 540; ip udp dport 8080 actions funnel tcp dport 80 sport 541;"
RULESET_INGRESS := "ip tcp sport 80 dport 540 actions unfunnel tcp"
SRC_IPS := 192.168.254.2 192.168.254.3 192.168.254.4 192.168.254.5 192.168.254.6 192.168.254.7 192.168.254.8 192.168.254.9 192.168.254.10 192.168.254.11

all: check
check: _start_minikube _compile _deploy _create_ns _load _check_affinity
clean: _delete_ns _stop_minikube

_start_minikube:
	$(QUIET) minikube start --nodes $(NODES) --cni=$(CNI) --cpus=$(CPUS) --addons=metallb
	$(QUIET) if [[ "$(CILIUM_KPR)" == "1" ]]; then \
	           echo "Setting kube-proxy-replacement=true..."; \
	           cilium config set kube-proxy-replacement true; \
	           echo "Waiting for cilium to restart..."; \
	           while [[ "$$(minikube kubectl -- -n kube-system get pods | grep cilium- | grep -v envoy | grep -v operator | grep Running)" == "" ]]; do sleep 1; done; \
	         fi
_stop_minikube:
	$(QUIET) minikube delete || true

_create_ns:
	$(QUIET) sudo ip netns add client
	$(QUIET) sudo ip link add type veth
	$(QUIET) sudo ip link set up dev veth0
	$(QUIET) sudo ip link set netns client veth1
	$(QUIET) sudo ip addr add 192.168.254.1/24 dev veth0
	$(QUIET) sudo ip netns exec client ip link set up dev veth1
	$(QUIET) for IP in $(SRC_IPS); do sudo ip netns exec client ip addr add $${IP}/24 dev veth1; done
	$(QUIET) sudo ip netns exec client ip route add default via 192.168.254.1
	$(QUIET) sudo iptables -I FORWARD -s 10.0.0.0/8 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -d 10.0.0.0/8 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -s 192.168.240.0/20 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -d 192.168.240.0/20 -j ACCEPT
	$(QUIET) export MINIKUBE_IPS="$$(minikube kubectl -- get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')" && sudo ip route add 192.168.253.0/24 $$(for IP in $${MINIKUBE_IPS}; do echo "nexthop via $${IP}"; done)
	$(QUIET) sudo bash -c "echo 1 > /proc/sys/net/ipv4/ip_forward"
_delete_ns:
	$(QUIET) sudo ip route del $$(ip route show 192.168.253.0/24) || true
	$(QUIET) sudo iptables -D FORWARD -s 10.0.0.0/8 -j ACCEPT || true
	$(QUIET) sudo iptables -D FORWARD -d 10.0.0.0/8 -j ACCEPT || true
	$(QUIET) sudo iptables -D FORWARD -s 192.168.240.0/20 -j ACCEPT || true
	$(QUIET) sudo iptables -D FORWARD -d 192.168.240.0/20 -j ACCEPT || true
	$(QUIET) sudo ip link del veth0 || true
	$(QUIET) sudo ip netns del client || true

_deploy:
	$(QUIET) minikube kubectl -- apply -k .

_undeploy:
	$(QUIET) minikube kubectl -- delete -k . || true

_compile:
	$(QUIET) cd ../../docker && make
	$(QUIET) minikube image load sfunnel
_load:
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=client -e IFACES=veth1 -e SFUNNEL_RULESET=$(RULESET_EGRESS) -e DEBUG=1 -e DIRECTION=egress sfunnel
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=client -e IFACES=veth1 -e SFUNNEL_RULESET=$(RULESET_INGRESS) -e DEBUG=1 -e DIRECTION=ingress sfunnel
_unload:
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=client -e IFACES=veth1 -e CLEAN=1 -e DEBUG=1 -e DIRECTION=both sfunnel

_wait_up:
	$(QUIET) echo "Waiting for service to be up..."
	$(QUIET) while [[ "$$(kubectl get service my-loadbalancer-service | grep pending)" != "" ]]; do sleep 1; done
	$(QUIET) echo "Service is up!"

_wait_running:
	$(QUIET) echo "Waiting for all pods to be up & running..."
	$(QUIET) while [[ "$$(minikube kubectl -- get pods | grep my-nginx-deployment | grep -v Running)" != "" ]]; do sleep 1; done
	$(QUIET) echo "All up!"

_check_affinity: _wait_up _wait_running
	$(QUIET) SRC_IPS="$(SRC_IPS)" ITERATIONS=$(ITERATIONS) ./check_affinity.sh
