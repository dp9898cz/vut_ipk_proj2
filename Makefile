# Makefile pro projekt 2 do IPK (varianta ZETA)
# Daniel Pátek (xpatek08)
# VUT FIT 2020

CC=gcc
CFLAGS=-c -Wall -D_GNU_SOURCE
LDFLAGS=-lpcap

.PHONY: all sniffer.c sniffer

all: sniffer.c sniffer

sniffer: sniffer.o 
	$(CC) $^ -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -I. $< -o $@

clean:
	rm -rf sniffer.o sniffer
