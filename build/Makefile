# 1) Don't give files that aren't direct children of test/ the `test_` prefix
# 2) Don't give files that are not automatically generated the `_runner.c` suffix
# 3) Don't give files that are not automatically generated the `mock_` prefix

#######################
# Begin Configuration #
#######################

SRC_ROOT	:= ../src
VENDR_ROOT	:= ../vendor
TEST_ROOT	:= ../test
CONFIG_ROOT	:= ../config

UNITY_ROOT	:= $(VENDR_ROOT)/unity
CMOCK_ROOT	:= $(VENDR_ROOT)/cmock
RUNR_ROOT	:= $(TEST_ROOT)/runners

# This is the name of the resulant executable
EXENAME	:= buselfs

# This file houses the int main() function for the executable (and nothing else)
# This should be the only file with a main() function in SRC_ROOT; there should be no tests for it, either
EXECSRC	:= $(SRC_ROOT)/main.c

# This should be in VENDR_ROOT
STATIC_LIB := $(VENDR_ROOT)/libbuse.a $(VENDR_ROOT)/libmerkletree_32_20.a

CC  := /usr/bin/gcc
CCV := $(shell expr `gcc --version | grep ^gcc | awk '{print $$3}'` \>= 4.9)

DEBUGFLAGS 	:= -g
CONDITIONALDEBUGFLAGS := -fsanitize=address,undefined,shift,integer-divide-by-zero,null,signed-integer-overflow \
						 -fno-omit-frame-pointer

CFLAGS		:= -pedantic -Wall -Wextra -std=c11

IFLAGS		:= -I/usr/local/include \
			   -I. \
			   -I$(VENDR_ROOT) \
			   -I$(CONFIG_ROOT) \
			   -I$(SRC_ROOT) \
			   -I$(UNITY_ROOT)/src \
			   -I$(CMOCK_ROOT)/src

LDFLAGS		:= -L$(VENDR_ROOT) -L/usr/local/lib \
				-lbuse -lsodium -lzlog -lpthread -lm

# Ruby configs for runner generation w/ Unity (auto)
GENRNR_CONF	:= $(CONFIG_ROOT)/unity_runner_config.yml

# Ruby configs for mock generation. :mock_prefix should be set to mock_
CMOCK_CONF := $(CONFIG_ROOT)/cmock_config.yml

# List of header file names (no .h or any other extensions) in SRC_ROOT to mock with cmock
# e.g. HDRS_TO_MOCK := interactions my_lib
# You can then include the mocked header e.g. #include "mock_my_lib.h"
HDRS_TO_MOCK := 

#####################
# End Configuration #
#####################

vpath %_runner.c $(RUNR_ROOT)
vpath test_% $(TEST_ROOT)
vpath % $(SRC_ROOT) $(VENDR_ROOT) $(CONFIG_ROOT)

SRC_FILES	:= $(patsubst %.c,%.o,$(subst $(SRC_ROOT)/,,$(filter-out $(EXECSRC),$(wildcard $(SRC_ROOT)/*.c))))
VENDR_FILES	:= $(patsubst %.c,%.o,$(subst $(VENDR_ROOT)/,,$(wildcard $(VENDR_ROOT)/*.c)))

TEST_TRGTS	:= $(patsubst %.c,%,$(subst $(TEST_ROOT)/,,$(wildcard $(TEST_ROOT)/*.c)))
RUNR_TRGTS	:= $(patsubst %,%_runner.c,$(TEST_TRGTS))

MOCK_TRGTS	:= $(patsubst %,mock_%.h,$(HDRS_TO_MOCK))

ifeq "$(CCV)" "1"
	DEBUGFLAGS += $(CONDITIONALDEBUGFLAGS)
endif

.PHONY: all all-O0 all-O2 all-O3 tests tests-O0 tests-O2 tests-O3 O0 O2 O3 clean check vendor src mocks

all-O3: O3 all
all-O2: O2 all
all-O0: O0 all

all: $(EXENAME)

$(EXENAME): $(VENDR_FILES) $(SRC_FILES)
	$(CC) $(CFLAGS) $(IFLAGS) $(LDFLAGS) -o $(EXENAME) $(EXECSRC) $(STATIC_LIB) $^

$(VENDR_FILES) $(SRC_FILES): %.o: %.c %.h
	$(CC) $(CFLAGS) $(IFLAGS) -o $@ -c $<

$(TEST_TRGTS): test_%: %.c test_%.c test_%_runner.c
	$(CC) $(CFLAGS) $(DEBUGFLAGS) $(IFLAGS) $(LDFLAGS) -o $@ \
		$^ \
		$(UNITY_ROOT)/src/unity.c \
		$(CMOCK_ROOT)/src/cmock.c \
		$(VENDR_FILES) \
		$(filter-out mock_$*.c,$(wildcard mock_*.c)) \
		$(STATIC_LIB)

$(RUNR_TRGTS): %_runner.c: %.c
	ruby $(UNITY_ROOT)/auto/generate_test_runner.rb $< $@ $(GENRNR_CONF)

O0:
	$(eval CFLAGS += -O0)

O2:
	$(eval CFLAGS += -O2)

O3:
	$(eval CFLAGS += -O3)

clean:
	find . -not -name 'Makefile' -not -name '.gitignore' -type f -exec rm {} +

check: tests
	$(patsubst %,./% &&,$(TEST_TRGTS)) true

vendor: $(VENDR_FILES)

src: $(SRC_FILES)

tests: vendor mocks $(TEST_TRGTS)

tests-O3: O3 tests
tests-O2: O2 tests
tests-O0: O0 tests

mocks: $(MOCK_TRGTS)

$(MOCK_TRGTS): mock_%: %
	ruby $(CMOCK_ROOT)/lib/cmock.rb -o$(CMOCK_CONF) $<


