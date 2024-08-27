.PHONY: check run_checks setup load unload compile show clean

ifeq ($(VERBOSE),1)
    QUIET :=
else
    QUIET := @
endif

all: check

check: compile setup load run_checks clean raise_errors

run_checks:
	$(QUIET)sudo pytest -s unit_test.py || (echo 1 > .errors)
raise_errors:
	$(QUIET)([ ! -f .errors ] && echo "SUCCESS") || (echo "ERROR: tests failed!" && exit 1)
setup:
	$(QUIET)sudo rm -rf .errors
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link add type veth
	$(QUIET)sudo ip link set up dev veth0
	$(QUIET)sudo ip link set up dev veth1
	$(QUIET)sudo ip link set up dev veth2
	$(QUIET)sudo ip link set up dev veth3
	$(QUIET)sudo brctl addbr br_net
	$(QUIET)sudo ip link set up dev br_net
	$(QUIET)sudo brctl addif br_net veth1
	$(QUIET)sudo brctl addif br_net veth2
	$(QUIET)sudo tc qdisc add dev veth0 clsact
	$(QUIET)sudo tc qdisc add dev veth1 clsact
	$(QUIET)sudo tc qdisc add dev veth2 clsact
	$(QUIET)sudo tc qdisc add dev veth3 clsact
	$(QUIET)sudo ip netns add pod
	$(QUIET)sudo ip link set netns pod dev veth3
	$(QUIET)sudo ip addr add 10.0.0.1/24 dev br_net
	$(QUIET)sudo ip netns exec pod ip link set up dev veth3
	$(QUIET)sudo ip netns exec pod ip addr add 10.0.0.2/24 dev veth3

load:
	$(QUIET)sudo tc filter add dev veth1 ingress bpf da obj ./tc_sfunnel.o sec funnel verbose
	$(QUIET)sudo tc filter add dev veth2 egress bpf da obj ./tc_sfunnel.o sec funnel verbose

unload:
	$(QUIET)sudo tc filter del dev veth1 ingress || true
	$(QUIET)sudo tc filter del dev veth2 egress || true

compile:
	$(QUIET)rm ../src/ruleset.h || true
	$(QUIET)python3 ../tools/gen.py ../src/ruleset.default > ruleset.h
	$(QUIET)clang -DTEST_TCP_FUNNELING=1 -O2 -Wall -Werror -I./ -g -target bpf -c ../src/sfunnel.c -o tc_sfunnel.o

show:
	$(QUIET)sudo tc filter show dev veth0 ingress
	$(QUIET)sudo tc filter show dev veth0 egress
	$(QUIET)sudo tc filter show dev veth1 ingress
	$(QUIET)sudo tc filter show dev veth1 egress
	$(QUIET)sudo tc filter show dev veth2 ingress
	$(QUIET)sudo tc filter show dev veth2 egress
	$(QUIET)sudo ip netns exec pod tc filter show dev veth3 ingress
	$(QUIET)sudo ip netns exec pod tc filter show dev veth3 egress

clean: unload
	$(QUIET)rm -rf *.o || true
	$(QUIET)sudo ip link del veth0 || true
	$(QUIET)sudo ip link del veth2 || true
	$(QUIET)sudo ip netns del pod || true
	$(QUIET)sudo ip link set down dev br_net || true
	$(QUIET)sudo brctl delbr br_net || true
