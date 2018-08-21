# Copyright 2018, Oliver Janssen
#
# This file is partly based on source code released by
# the PMDK project found at https://github.com/pmem/pmdk which is covered
# by the license found under the file LICENSE in the root folder.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

TOP := $(dir $(lastword $(MAKEFILE_LIST)))../..

include $(TOP)/src/common.inc

vpath %.c $(TOP)/src/libpmemobj
vpath %.c $(TOP)/src/common

BENCHMARK = mp_bench
WORKER = mp_bench_worker
GLIB:= $(call check_package, glib-2.0)
ifeq ($(GLIB),y)
TARGET = $(BENCHMARK) $(WORKER)
else
$(info NOTE: Skipping mp_bench because glib-2.0 is missing \
-- see src/benchmarks/README for details.)
endif

all: $(TARGET)

SRC=mp_bench.c\
    benchmark_time.c\

SRC_WORKER=mp_bench_worker.c\
           benchmark_time.c\

OBJS=$(SRC:.c=.o)
OBJS_WORKER=$(SRC_WORKER:.c=.o)

ifneq ($(filter 1 2, $(CSTYLEON)),)
TMP_HEADERS := $(addsuffix tmp, $(HEADERS))
endif
LDFLAGS = -L$(LIBS_PATH)
LDFLAGS += $(EXTRA_LDFLAGS)
ifeq ($(DEBUG),)
LIBS += ../nondebug/libpmemcommon.a
else
LIBS += ../debug/libpmemcommon.a
endif
LIBS += -lpmemobj -lpmem -pthread -lm -ldl
LIBS += -lrt
ifeq ($(call check_librt), n)
LIBS += -lrt
endif

CFLAGS += -std=gnu99
CFLAGS += -Wall
CFLAGS += -Werror
CFLAGS += -Wmissing-prototypes
CFLAGS += -Wpointer-arith
CFLAGS += -Wunused-macros
CFLAGS += -Wmissing-field-initializers
#CFLAGS += -Wsign-conversion
CFLAGS += -Wsign-compare

##CFLAGS += -std=c++0x
##CFLAGS += -Wno-invalid-offsetof
CFLAGS += -pthread
CFLAGS += -I../include
CFLAGS += -I../libpmemobj
CFLAGS += -I../common
CFLAGS += -DSRCVERSION='"$(SRCVERSION)"'

ifeq ($(COVERAGE),1)
CFLAGS += $(GCOV_CFLAGS)
LDFLAGS += $(GCOV_LDFLAGS)
LIBS += $(GCOV_LIBS)
endif

ifneq ($(SANITIZE),)
CFLAGS += -fsanitize=$(SANITIZE)
LDFLAGS += -fsanitize=$(SANITIZE)
endif

ifeq ($(GLIB),y)
CFLAGS += $(shell $(PKG_CONFIG) --cflags glib-2.0)
LIBS += $(shell $(PKG_CONFIG) --libs glib-2.0)
endif

OBJS += pmemobj.o
OBJS_WORKER += pmemobj.o

ifeq ($(DEBUG),)
CFLAGS += -O3
LIBS_PATH=../nondebug
else
CFLAGS += -ggdb
LIBS_PATH=../debug
endif

GLIB_TEST_PROG="\#include <glib.h>\nint main(){return 0;}"
GLIB_SILENCE := $(shell printf $(GLIB_TEST_PROG) |\
	$(CC) $(CFLAGS) -x c -o /dev/null - 2>/dev/null && echo n || echo y)

ifeq ($(GLIB_SILENCE), y)
CFLAGS += -Wno-unknown-attributes
endif

CFLAGS += $(EXTRA_CFLAGS)

objdir=.

%.o: %.c Makefile
	$(call check-cstyle, $<)
	@mkdir -p .deps
	$(CC) -MD -c -o $@ $(CFLAGS) $(call coverage-path, $<)
	$(call check-os, $@, $<)
	$(create-deps)

%.htmp: %.h
	$(call check-cstyle, $<, $@)

%.hpptmp: %.hpp
	$(call check-cstyle, $<, $@)

$(BENCHMARK): $(TMP_HEADERS) $(OBJS)
	$(CC) -o $@ $(LDFLAGS) $(OBJS) $(LIBS)

$(WORKER): $(TMP_HEADERS) $(OBJS_WORKER)
	$(CC) -o $@ $(LDFLAGS) $(OBJS_WORKER) $(LIBS)

clean:
	$(RM) $(OBJS) $(TMP_HEADERS)
	$(RM) *.csv

clobber: clean
	$(RM) $(BENCHMARK)
	$(RM) *.csv
	$(RM) -r .deps

#$(CONFIGS):
#	LD_LIBRARY_PATH=$(LIBS_PATH) ./$(BENCHMARK) $@.cfg > $@.csv

#run: $(BENCHMARK) $(CONFIGS)
run: $(BENCHMARK)

sparse:

.PHONY: all clean clobber run $(CONFIGS)

PMEMOBJ_SYMBOLS=pmalloc pfree lane_hold lane_release

pmemobj.o: $(LIBS_PATH)/libpmemobj/libpmemobj_unscoped.o
	objcopy --localize-hidden $(addprefix -G, $(PMEMOBJ_SYMBOLS)) $< $@

-include .deps/*.P