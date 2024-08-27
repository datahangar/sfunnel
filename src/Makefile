all: compile

FILE := $(or $(wildcard ruleset), ruleset.default)

compile:
	python3 ../tools/gen.py $(FILE) > ruleset.h
	clang -O2 -Wall -Werror -g -target bpf -c sfunnel.c -o tc_sfunnel.o

clean:
	rm -rf *.o || true
	rm -rf ruleset.h || true
