# phase2/Makefile — DH + AES-256-GCM chat server, client and MITM proxy.
#
#   make            build server, client, mitm
#   make clean      remove build output

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDLIBS   ?= -pthread -lcrypto

COMMON := proto.o dh.o crypto.o session.o

.PHONY: all clean test

all: server client mitm selftest

server: server.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

client: client.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

mitm: mitm.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

selftest: selftest.o dh.o crypto.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

test: selftest
	./selftest

%.o: %.cpp proto.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f server client mitm selftest *.o
