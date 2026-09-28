#####################
# Special credits to the following devs that make this YiiMP stratum possible
# tpruvot https://github.com/tpruvot/yiimp
# barrystyle https://github.com/barrystyle
# Alexg Discord
# Kudaraidee https://github.com/Kudaraidee/yiimp
# And all the other devs that have helped with this project
#####################
#
# Build dependencies (Ubuntu 22.04 / 24.04 / 26.04):
#   build-essential pkg-config libmysqlclient-dev (or libmariadb-dev-compat)
#   libcurl4-openssl-dev (or libcurl4-gnutls-dev) libssl-dev libgmp-dev
#
# Everything is linked dynamically against the distribution libraries.

CC=gcc
CXX=g++

# Portable by default so the binary keeps working if the VM moves to another
# CPU model; build with "make MARCH=native" to tune for this machine.
MARCH ?= x86-64-v2
CFLAGS= -g -O2 -march=$(MARCH) -fno-strict-aliasing
SQLFLAGS= `mysql_config --cflags`

# Comment this line to disable address check on login,
# if you use the auto exchange feature...
CFLAGS += -DNO_EXCHANGE

CXXFLAGS= -std=gnu++17 -Werror=return-type -Wno-format-truncation -MMD -MP

LDFLAGS=
LDLIBS=iniparser/libiniparser.a algos/libalgos.a sha3/libhash.a
LDLIBS+=`mysql_config --libs`
LDLIBS+=$(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)
LDLIBS+=-lpthread -lgmp -lm -lstdc++

SOURCES=stratum.cpp db.cpp coind.cpp coind_aux.cpp coind_template.cpp coind_submit.cpp util.cpp list.cpp \
	rpc.cpp job.cpp job_send.cpp job_core.cpp merkle.cpp share.cpp socket.cpp coinbase.cpp \
	client.cpp client_submit.cpp client_core.cpp client_difficulty.cpp remote.cpp remote_template.cpp \
	user.cpp object.cpp json.cpp base58.cpp protocol.cpp protocol_kawpow.cpp protocol_equihash.cpp

CFLAGS += -DHAVE_CURL
SOURCES += rpc_curl.cpp
LDCURL = $(shell pkg-config --libs libcurl 2>/dev/null || echo -lcurl)
LDLIBS += $(LDCURL)

OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=stratum

LIBS=iniparser/libiniparser.a algos/libalgos.a sha3/libhash.a

.PHONY: all clean install libs

all: $(OUTPUT)

# the sub-makes decide themselves whether something needs rebuilding
libs:
	$(MAKE) -C iniparser libiniparser.a
	$(MAKE) -C algos
	$(MAKE) -C sha3

$(LIBS): libs

$(OBJECTS): stratum.h util.h Makefile

$(OUTPUT): $(OBJECTS) $(LIBS)
	$(CXX) $(LDFLAGS) $(OBJECTS) $(LDLIBS) -o $@

# hash regression test, not built by default: make hashtest && ./hashtest
hashtest: hashtest.o $(LIBS)
	$(CXX) $(LDFLAGS) hashtest.o $(LIBS) $(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto) -lpthread -lgmp -lm -o $@

# verthash.dat generator for the verthash stratum: make verthash_gen && ./verthash_gen <file>
verthash_gen: verthash_gen.c algos/verthash.h
	$(CC) -O2 -std=gnu17 -o $@ verthash_gen.c $(shell pkg-config --libs libcrypto 2>/dev/null || echo -lcrypto)

.cpp.o:
	$(CXX) $(CFLAGS) $(CXXFLAGS) $(SQLFLAGS) -c $<

-include $(OBJECTS:.o=.d) hashtest.d

clean:
	rm -f *.o *.d $(OUTPUT) hashtest verthash_gen
	$(MAKE) -C algos clean
	$(MAKE) -C sha3 clean
	$(MAKE) -C iniparser clean

install: clean all
	strip -s stratum
	cp stratum /usr/local/bin/
	cp stratum ../bin/
