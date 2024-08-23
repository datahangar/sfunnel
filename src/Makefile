all: compile

compile:
	clang -O2 -Wall -Werror -g -target bpf -c funnel.c -o tc_funnel.o
	clang -O2 -Wall -Werror -g -target bpf -c unfunnel.c -o tc_unfunnel.o

clean:
	rm -rf *.o || true
