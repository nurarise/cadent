.DELETE_ON_ERROR:
.PHONY: clean all
CC=gcc
COPTS=-Wall -W -Wextra -Werror
LDLIBS=

OUT?=.out

BIN=cadentwifi

CADENTSDIR:=src
CADENTSRC:=$(shell find $(CADENTSDIR) -type f -name \*.c -print)
CADENTOBJ:=$(addprefix $(OUT)/,$(CADENTSRC:%.c=%.o))

all: bin

bin: $(addprefix $(OUT)/,$(BIN))

$(OUT)/cadentwifi: $(CADENTOBJ)
	@mkdir -p $(@D)
	$(CC) -o $@ $< $(LDLIBS)

$(OUT)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(COPTS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(OUT) $(wildcard core*)
