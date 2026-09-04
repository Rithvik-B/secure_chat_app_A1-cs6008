# phase3/Makefile — authenticated (PKI) chat server, client, MITM proxy.
#
#   make            build server, client, mitm, selftest, certcheck
#   make test       run the crypto self-test
#   make clean      remove build output

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDLIBS   ?= -pthread -lcrypto

COMMON := proto.o dh.o crypto.o pki.o session.o e2e.o

.PHONY: all clean test

all: server client mitm selftest certcheck

server: server.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

client: client.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

mitm: mitm.o $(COMMON)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

selftest: selftest.o dh.o crypto.o e2e.o proto.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

certcheck: certcheck.o pki.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

test: selftest
	./selftest

%.o: %.cpp proto.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f server client mitm selftest certcheck *.o
