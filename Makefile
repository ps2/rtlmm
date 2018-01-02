all: rtlmm

CC = gcc
GCCVERSION = $(shell gcc --version | grep ^gcc | sed 's/^.* //g')

CFLAGS	=

ifeq "$(GCCVERSION)" "4.9.2"
    CFLAGS = -std=gnu99
endif

CFLAGS  += -Wall -g -O2 -Wno-unused-variable

LDFLAGS	= -lm -lliquid

rtlmm.o: rtlmm.c
		$(CC) $(CFLAGS) -o rtlmm.o -c rtlmm.c

fourbsixb.o: fourbsixb.c
		$(CC) $(CFLAGS) -o fourbsixb.o -c fourbsixb.c

ook.o: ook.c
		$(CC) $(CFLAGS) -o ook.o -c ook.c

rtlmm: rtlmm.o fourbsixb.o ook.o
		$(CC) -o rtlmm rtlmm.o fourbsixb.o ook.o $(LDFLAGS)
