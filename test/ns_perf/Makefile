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

ifeq ($(PROTO),udp)
  PROTO := udp
  IPERF_OPTS := -u -l 1430 -b 100G
else
  PROTO := tcp
endif

ifeq ($(FUN_PROTO),udp)
  FUN_PROTO := udp
else
  FUN_PROTO := tcp
endif

CLANG ?= clang
MTU := 1500

all: check
check: _setup _load

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

RULES_SVC_EGRESS  := "ip $(PROTO) sport 8080 actions funnel $(FUN_PROTO) sport 80 dport 540"
RULES_SVC_INGRESS := "ip $(FUN_PROTO) dport 80 sport 540 actions unfunnel $(PROTO)"

RULES_INGRESS     := "ip $(FUN_PROTO) sport 80 dport 540 actions unfunnel $(PROTO)"
RULES_EGRESS      := "ip $(PROTO) dport 8080 actions funnel $(FUN_PROTO) sport 540 dport 80"

_setup:
	$(QUIET)echo -n "Creating ifaces..."
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link add type veth
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Creating ns1, ns2..."
	$(QUIET)sudo ip netns add ns1
	$(QUIET)sudo ip netns add ns2
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Moving: eth0=>ns1, eth3=>n2..."
	$(QUIET)sudo ip link set netns ns1 dev veth0
	$(QUIET)sudo ip link set netns ns2 dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Bringing them up..."
	$(QUIET)sudo ip link set up dev veth1
	$(QUIET)sudo ip link set up dev veth2
	$(QUIET)sudo ip netns exec ns1 ip link set up dev lo
	$(QUIET)sudo ip netns exec ns2 ip link set up dev lo
	$(QUIET)sudo ip netns exec ns1 ip link set up dev veth0
	$(QUIET)sudo ip netns exec ns2 ip link set up dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Setting MTU..."
	$(QUIET)sudo ip netns exec ns1 ip link set mtu $(MTU) dev veth0
	$(QUIET)sudo ip link set mtu $(MTU) dev veth1
	$(QUIET)sudo ip link set mtu $(MTU) dev veth2
	$(QUIET)sudo ip netns exec ns2 ip link set mtu $(MTU) dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Add IP addresses..."
	$(QUIET)sudo ip netns exec ns1 ip addr add 10.0.0.1/24 dev veth0
	$(QUIET)sudo ip addr add 10.0.0.2/24 dev veth1
	$(QUIET)sudo ip addr add 10.0.1.1/24 dev veth2
	$(QUIET)sudo ip netns exec ns2 ip addr add 10.0.1.2/24 dev veth3
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Add default routes to NSs..."
	$(QUIET)sudo ip netns exec ns1 ip route add default via 10.0.0.2
	$(QUIET)sudo ip netns exec ns2 ip route add default via 10.0.1.1
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Open the firewall..."
	$(QUIET)sudo iptables -I FORWARD -d 10.0.0.0/8 -j ACCEPT
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Disable RPF filters..."
	$(QUIET)sudo ip netns exec ns1 sysctl -q net.ipv4.conf.veth0.rp_filter=0
	$(QUIET)sudo sysctl -q net.ipv4.conf.veth1.rp_filter=0
	$(QUIET)sudo sysctl -q net.ipv4.conf.veth2.rp_filter=0
	$(QUIET)sudo ip netns exec ns2 sysctl -q net.ipv4.conf.veth3.rp_filter=0
	$(QUIET)echo "OK"
	$(QUIET)echo -n "Test base setup..."
	$(QUIET)sudo ip netns exec ns1 ping -c 1 10.0.1.2 > /dev/null
	$(QUIET)echo "OK"

_compile:
	$(QUIET)cd ../../docker && make

_load: _compile
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns1 -e IFACES=veth0 -e SFUNNEL_RULESET=$(RULES_EGRESS) -e DIRECTION=egress -e DEBUG=$(DEBUG) sfunnel
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns1 -e IFACES=veth0 -e SFUNNEL_RULESET=$(RULES_INGRESS) -e DIRECTION=ingress -e DEBUG=$(DEBUG) sfunnel
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns2 -e IFACES=veth3 -e SFUNNEL_RULESET=$(RULES_SVC_EGRESS) -e DIRECTION=egress -e DEBUG=$(DEBUG) sfunnel
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns2 -e IFACES=veth3 -e SFUNNEL_RULESET=$(RULES_SVC_INGRESS) -e DIRECTION=ingress -e DEBUG=$(DEBUG) sfunnel

_unload:
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns1 -e CLEAN=1 -e DEBUG=1 -e DIRECTION=both sfunnel
	$(QUIET)docker run --privileged --network=host -v /var/run/netns:/var/run/netns -i -e NETNS=ns2 -e CLEAN=1 -e DEBUG=1 -e DIRECTION=both sfunnel


_clean_iperf:
	$(QUIET)sudo ip netns exec ns1 killall iperf || true
	$(QUIET)sudo ip netns exec ns2 killall iperf || true

# No DNAT/SNAT
check_perf_calibration:
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 80 $(IPERF_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.2 -p 80 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_iperf
check_perf:
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 8080 $(IPERF_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.2 -p 8080 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_iperf

# DNAT only
_clean_dnat:
	$(QUIET)sudo iptables -t nat -D PREROUTING -s 10.0.0.1 -d 10.0.1.3 -j DNAT --to-destination 10.0.1.2 || true
	$(QUIET)sudo iptables -t nat -D POSTROUTING -s 10.0.1.2 -d 10.0.0.1 -j SNAT --to-source 10.0.1.3 || true
_add_dnat:
	$(QUIET)echo -n "Add DNAT..."
	$(QUIET)sudo iptables -t nat -I PREROUTING -s 10.0.0.1 -d 10.0.1.3 -j DNAT --to-destination 10.0.1.2
	$(QUIET)sudo iptables -t nat -I POSTROUTING -s 10.0.1.2 -d 10.0.0.1 -j SNAT --to-source 10.0.1.3
	$(QUIET)echo "OK"
check_perf_calibration_dnat: _add_dnat
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 80 $(IPERF_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.3 -p 80 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_dnat
	$(QUIET) $(MAKE) _clean_iperf
check_perf_dnat: _add_dnat
	$(QUIET)sudo ip netns exec ns2 iperf -s -p 8080 $(IPERF_OPTS) &
	$(QUIET)sudo ip netns exec ns1 iperf -c 10.0.1.3 -p 8080 $(IPERF_OPTS)
	$(QUIET) $(MAKE) _clean_dnat
	$(QUIET) $(MAKE) _clean_iperf

clean: _clean_dnat _clean_iperf
	$(QUIET)sudo iptables -D FORWARD -d 10.0.0.0/8 -j ACCEPT || true
	$(QUIET)sudo ip link del veth1 || true
	$(QUIET)sudo ip link del veth2 || true
	$(QUIET)sudo ip netns del ns1 || true
	$(QUIET)sudo ip netns del ns2 || true
