# phase1/Makefile — plaintext chat server and client.
#
#   make            build both binaries
#   make clean      remove build output

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -O2
LDLIBS   ?= -pthread

BINARIES := server client
OBJS     := proto.o server.o client.o

.PHONY: all clean

all: $(BINARIES)

server: server.o proto.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

client: client.o proto.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.cpp proto.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(BINARIES) $(OBJS)
