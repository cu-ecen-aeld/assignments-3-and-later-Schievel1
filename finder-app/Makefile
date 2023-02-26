##
# assignment2-Schievel1
#
# @file
# @version 0.1

CC ?= gcc
CFLAGS += -Wall
CFLAGS += -Werror

ifeq ($(DEBUG),true)
	CFLAGS += -g
endif

default:
	$(CROSS_COMPILE)gcc writer.c -o writer

clean:
	rm -rf *.o writer
# end
