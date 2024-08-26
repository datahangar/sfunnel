all: compile

compile:
	python3 ../tools/gen.py rules.default > rules.h
	clang -O2 -Wall -Werror -g -target bpf -c sfunnel.c -o tc_sfunnel.o

clean:
	rm -rf *.o || true
	rm -rf rules.h || true
