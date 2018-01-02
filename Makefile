all: rtlmm

CC = gcc
GCCVERSION = $(shell gcc --version | grep ^gcc | sed 's/^.* //g')

CFLAGS	=

ifeq "$(GCCVERSION)" "4.9.2"
    CFLAGS = -std=gnu99
endif

CFLAGS  += -Wall -g -O2 -Wno-unused-variable

LDFLAGS	= -lm -lliquid


rtlmm: rtlmm.c
		$(CC) $(CFLAGS) -o rtlmm rtlmm.c $(LDFLAGS)
