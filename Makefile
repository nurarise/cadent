.DELETE_ON_ERROR:
.PHONY: clean all
CC=gcc
COPTS=-Wall -W -Wextra -Werror
LDLIBS=
CFLAGS=$(COPTS)
OUT?=.out

BIN=cadent-wifi

CADENTSDIR:=src
CADENTINC:=$(shell find $(CADENTSDIR) -type f -name \*.h -print)
CADENTSRC:=$(shell find $(CADENTSDIR) -type f -name \*.c -print)
CADENTOBJ:=$(addprefix $(OUT)/,$(CADENTSRC:%.c=%.o))
DEPS=$(CADENTINC)

all: bin

bin: $(addprefix $(OUT)/,$(BIN))

$(OUT)/cadent-wifi: $(CADENTOBJ)
	@mkdir -p $(@D)
	$(CC) -o $@ $^ $(LDLIBS)

$(OUT)/%.o: %.c $(DEPS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUT) $(wildcard core*)
