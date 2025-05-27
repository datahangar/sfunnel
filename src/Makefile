all: compile

INGRESS ?= 1
SEG_DEV_IFINDEX ?= 0
SEG_PAIR_DEV_IFINDEX ?= 0
SEG_PAIR_DEV_MAC ?= 0x00,0x00,0x00,0x00,0x00,0x00
PMTUD_MAP_NAME ?= sfunnel_pmtud
PMTUD_MAP_N_ENTRIES ?= 1024
FILE ?= ruleset.default
CFLAGS = -O2 -Wall -Werror --std=gnu99 -g
ifeq ($(DEBUG), 1)
    CFLAGS += -DDEBUG=1
endif

compile:
	python3 -Werror ../tools/gen.py $(FILE) > ruleset.h
	clang $(CFLAGS) -DINGRESS=$(INGRESS) \
			-DSEG_PAIR_DEV_MAC="$(SEG_PAIR_DEV_MAC)" \
			-DSEG_DEV_IFINDEX=$(SEG_DEV_IFINDEX) \
			-DSEG_PAIR_DEV_IFINDEX=$(SEG_PAIR_DEV_IFINDEX) \
			-DPMTUD_MAP_NAME=$(PMTUD_MAP_NAME) \
			-DPMTUD_MAP_N_ENTRIES=$(PMTUD_MAP_N_ENTRIES) \
			-target bpf -c sfunnel.c -o tc_sfunnel.o

clean:
	rm -rf *.o || true
	rm -rf ruleset.h || true
