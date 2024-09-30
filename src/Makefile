all: compile

FILE ?= ruleset.default
CFLAGS = -O2 -Wall -Werror -g
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG=1
endif

compile:
	python3 ../tools/gen.py $(FILE) > ruleset.h
	clang $(CFLAGS) -target bpf -c sfunnel.c -o tc_sfunnel.o

clean:
	rm -rf *.o || true
	rm -rf ruleset.h || true
