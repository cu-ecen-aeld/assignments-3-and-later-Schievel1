##
# aesdsocket
#
# @file
# @version 0.1

INCLUDES ?=
LIB_DIRS =
CROSS_COMPILE =
CC ?= $(CROSS_COMPILE)gcc
TARGET ?= aesdsocket

CFLAGS ?= -O0 -g -Wall -Werror
LDFLAGS ?= -pthread -lrt

HFILES = queue.h
CFILES = $(TARGET).c

SRCS = ${HFILES} ${CFILES}
OBJS = ${CFILES:.c=.o}

all:	$(TARGET)

clean:
	-rm -f *.o *.d
	-rm -f $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(INCLUDES) $(LDFLAGS)

depend:

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<
