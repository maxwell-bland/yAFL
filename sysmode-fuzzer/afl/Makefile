#
# american fuzzy lop - makefile
# -----------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# Hacked apart by Maxwell Bland
# 
# Copyright 2013, 2014, 2015, 2016, 2017 Google LLC All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

PROGNAME    = afl
VERSION     = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

# PROGS intentionally omit afl-as, which gets installed elsewhere.

PROGS       = afl-fuzz sm-fuzzer

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl -lcriu
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: $(PROGS) all_done

afl-fuzz: afl-fuzz.c $(COMM_HDR) 
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

sm-fuzzer: sm-fuzzer.c sm-fuzzer.h $(COMM_HDR)
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

all_done:
	@echo "[+] All done! Be sure to review README - it's pretty short and useful."

.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test test-instr .test-instr0 .test-instr1 qemu_mode/qemu-2.10.0.tar.bz2
	rm -rf out_dir
