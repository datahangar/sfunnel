.PHONY: check run_checks setup load unload compile show clean

SHELL=/bin/bash

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

all: check

check: compile setup load run_checks clean raise_errors

##
## Test scenario
#
#  NS1                                         NS2
#  ...........                        ............
#  .  -----  .   -----        -----   .  -----   .
#  . |veth0|<-->|veth1|      |veth2|<-->|veth3|  .
#  .  -----  .   -----        -----   .  -----   .
#  ...........                        ............
#
## Addressing and routing
#
# NS1:
#  10.0.0.1/24 dev veth0
#  default via 10.0.0.2
#
# Default NS:
#  10.0.0.2/24 dev veth1
#  10.0.1.1/24 dev veth2
#  192.168.0./24 via 10.0.1.2
#
# NS2:
#  10.0.1.2/24 dev veth3
#
## Traffic
#
# Not NATed
# sip=10.0.0.1 dip=192.168.254.1 / UDP|TCP
#
# NATTed
# sip=10.0.0.1 dip=192.168.254.2 / UDP|TCP => sip=172.16.0.1 dip=192.168.254.3 / UDP|TCP
#

run_checks:
	$(QUIET)sudo pytest -s unit_test.py || (echo 1 > .errors)
raise_errors:
	$(QUIET)([ ! -f .errors ] && echo "SUCCESS") || (echo "ERROR: tests failed!" && exit 1)
setup:
	$(QUIET)sudo rm -rf .errors
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link set up dev veth1
	$(QUIET)sudo ip link set up dev veth2
	$(QUIET)sudo ip netns add ns1
	$(QUIET)sudo ip netns add ns2
	$(QUIET)sudo ip link set netns ns1 dev veth0
	$(QUIET)sudo ip link set netns ns2 dev veth3
	$(QUIET)sudo ip netns exec ns1 ip link set up dev veth0
	$(QUIET)sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth0
	$(QUIET)sudo ip addr add 10.0.0.2/24 dev veth1
	$(QUIET)sudo ip addr add 10.0.1.1/24 dev veth2
	$(QUIET)sudo ip netns exec ns2 ip link set up dev lo
	$(QUIET)sudo ip netns exec ns2 ip link set up dev veth3
	$(QUIET)sudo ip netns exec ns2 ip addr add 10.0.1.2/24 dev veth3
	$(QUIET)sudo ip netns exec ns2 ip addr add 192.168.254.1/32 dev lo
	$(QUIET)sudo ip netns exec ns2 ip addr add 192.168.254.2/32 dev lo
	$(QUIET)sudo ip netns exec ns1 tc qdisc add dev veth0 clsact
	$(QUIET)sudo tc qdisc add dev veth1 clsact
	$(QUIET)sudo iptables -I FORWARD -d 192.168.254.0/24 -j ACCEPT
	$(QUIET)sudo iptables -t nat -I PREROUTING  -i veth1 -s 10.0.0.1 -d 192.168.254.2 -j DNAT --to-destination 192.168.254.3
	$(QUIET)sudo iptables -t nat -I POSTROUTING -d 192.168.254.3 -j SNAT --to-source 172.16.0.1
	$(QUIET)sudo ip netns exec ns1 ip route add default via 10.0.0.2
	$(QUIET)sudo ip route add 192.168.254.0/24 via 10.0.1.2
	$(QUIET)sudo ip netns exec ns1 sysctl net.ipv4.conf.veth0.rp_filter=0
	$(QUIET)sudo sysctl net.ipv4.conf.veth1.rp_filter=0
	$(QUIET)sudo sysctl net.ipv4.conf.veth2.rp_filter=0
	$(QUIET)sudo ip netns exec ns2 sysctl net.ipv4.conf.veth3.rp_filter=0
	$(QUIET)sudo ip netns exec ns1 ethtool --offload veth0 rx off tx off
	$(QUIET)sudo ethtool --offload veth1 rx off tx off
	$(QUIET)sudo ethtool --offload veth2 rx off tx off
	$(QUIET)sudo ip netns exec ns2 ethtool --offload veth3 rx off tx off
load:
	$(QUIET)sudo ip netns exec ns1 tc filter add dev veth0 egress bpf da obj ./tc_sfunnel.o sec funnel verbose
	$(QUIET)sudo tc filter add dev veth1 ingress bpf da obj ./tc_sfunnel.o sec funnel verbose

unload:
	$(QUIET)sudo ip netns exec ns1 tc filter del dev veth0 egress || true
	$(QUIET)sudo tc filter del dev veth1 ingress || true

compile:
	$(QUIET)rm ../src/ruleset.h || true
	$(QUIET)python3 ../tools/gen.py ruleset > ruleset.h
	$(CLANG) -DDEBUG=$(DEBUG) -DTEST_TCP_FUNNELING=1 -O2 -Wall -Werror -I./ -g -target bpf -c ../src/sfunnel.c -o tc_sfunnel.o

clean: unload
	$(QUIET)rm -rf *.o || true
	$(QUIET)sudo iptables -D FORWARD -d 192.168.254.0/24 -j ACCEPT || true
	$(QUIET)sudo iptables -t nat -D PREROUTING  -i veth1 -s 10.0.0.1 -d 192.168.254.2 -j DNAT --to-destination 192.168.254.3 || true
	$(QUIET)sudo iptables -t nat -D POSTROUTING -d 192.168.254.3 -j SNAT --to-source 172.16.0.1 || true
	$(QUIET)sudo ip link del veth1 || true
	$(QUIET)sudo ip link del veth2 || true
	$(QUIET)sudo ip netns del ns1 || true
	$(QUIET)sudo ip netns del ns2 || true
