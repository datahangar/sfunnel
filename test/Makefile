all: compile setup load

setup:
	sudo ip link add type veth || true
	sudo ip link add type veth || true
	sudo ip link set up dev veth0 || true
	sudo ip link set up dev veth1 || true
	sudo ip link set up dev veth2 || true
	sudo ip link set up dev veth3 || true
	sudo brctl addbr br_net || true
	sudo ip link set up dev br_net || true
	sudo brctl addbr br_net || true
	sudo brctl addif br_net veth1 || true
	sudo brctl addif br_net veth2 || true
	sudo tc qdisc add dev veth0 clsact || true
	sudo tc qdisc add dev veth1 clsact || true
	sudo tc qdisc add dev veth2 clsact || true
	sudo tc qdisc add dev veth3 clsact || true
	sudo ip netns add pod || true
	sudo ip link set netns pod dev veth3 || true
	sudo ip addr add 10.0.0.1/24 dev br_net || true
	sudo ip netns exec pod ip link set up dev veth3 || true
	sudo ip netns exec pod ip addr add 10.0.0.2/24 dev veth3 || true

load:
	sudo tc filter add dev veth1 ingress bpf da obj ./tc_funnel.o sec funnel verbose
	sudo tc filter add dev veth2 egress bpf da obj ./tc_unfunnel.o sec funnel verbose

unload:
	sudo tc filter del dev veth1 ingress || true
	sudo tc filter del dev veth2 egress || true

compile:
	clang -O2 -Wall -Werror -g -target bpf -c ../src/funnel.c -o tc_funnel.o
	clang -O2 -Wall -Werror -g -target bpf -c ../src/unfunnel.c -o tc_unfunnel.o

show:
	sudo tc filter show dev veth0 ingress
	sudo tc filter show dev veth0 egress
	sudo tc filter show dev veth1 ingress
	sudo tc filter show dev veth1 egress
	sudo tc filter show dev veth2 ingress
	sudo tc filter show dev veth2 egress
	sudo ip netns exec pod tc filter show dev veth3 ingress
	sudo ip netns exec pod tc filter show dev veth3 egress

clean: unload
	rm -rf *.o || true
	sudo ip link del veth0 || true
	sudo ip link del veth2 || true
	sudo ip netns del pod || true
	sudo ip link set down dev br_net || true
	sudo brctl delbr br_net || true
