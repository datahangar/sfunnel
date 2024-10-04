.PHONY: all check

SHELL=/bin/bash

CNI ?= cilium
CPUS ?= 4

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
CLANG ?= clang

TIMER ?= 12
RULESET_EGRESS := "ip tcp dport 8080 actions funnel tcp dport 80 sport 540; ip udp dport 8080 actions funnel tcp dport 80 sport 541;"
RULESET_INGRESS := "ip tcp sport 80 dport 540 actions unfunnel tcp"

all: check
check: _start_minikube _compile _deploy _create_ns _wait_up _load _check_affinity
clean: _delete_ns _stop_minikube

_start_minikube:
	$(QUIET) minikube start --cni=$(CNI) --cpus=$(CPUS) --addons=metallb
_stop_minikube:
	$(QUIET) minikube delete || true

_create_ns:
	$(QUIET) sudo ip netns add client
	$(QUIET) sudo ip link add type veth
	$(QUIET) sudo ip link set up dev veth0
	$(QUIET) sudo ip link set netns client veth1
	$(QUIET) sudo ip addr add 192.168.254.1/24 dev veth0
	$(QUIET) sudo ip netns exec client ip link set up dev veth1
	$(QUIET) sudo ip netns exec client ip addr add 192.168.254.2/24 dev veth1
	$(QUIET) sudo ip netns exec client ip route add default via 192.168.254.1
	$(QUIET) sudo iptables -I FORWARD -s 10.0.0.0/8 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -d 10.0.0.0/8 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -s 192.168.240.0/20 -j ACCEPT
	$(QUIET) sudo iptables -I FORWARD -d 192.168.240.0/20 -j ACCEPT
	$(QUIET) export MINIKUBE_IP=$$(minikube ip) && sudo ip route add 192.168.253.0/24 via $$MINIKUBE_IP
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
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -it -e NETNS=client -e IFACES=veth1 -e SFUNNEL_RULESET=$(RULESET_EGRESS) -e DEBUG=1 -e DIRECTION=egress sfunnel
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -it -e NETNS=client -e IFACES=veth1 -e SFUNNEL_RULESET=$(RULESET_INGRESS) -e DEBUG=1 -e DIRECTION=ingress sfunnel
_unload:
	$(QUIET) docker run --privileged --network=host -v /var/run/netns:/var/run/netns -it -e NETNS=client -e IFACES=veth1 -e CLEAN=1 -e DEBUG=1 -e DIRECTION=both sfunnel

_wait_up:
	$(QUIET) echo "Waiting for service to be up..."
	$(QUIET) while [[ "$$(kubectl get service my-loadbalancer-service | grep pending)" != "" ]]; do sleep 1; done
	$(QUIET) echo "Service is up!"

_check_affinity:
	$(QUIET) ./check_affinity.sh $(TIMER)
