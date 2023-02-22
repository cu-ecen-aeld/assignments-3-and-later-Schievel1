##
# aesdsocket
#
# @file
# @version 0.1

CC ?= gcc
CFLAGS += -Wall
CFLAGS += -Werror

ifeq ($(DEBUG),true)
	CFLAGS += -g
endif


default all:
	$(CROSS_COMPILE)$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
	rm -rf *.o aesdsocket
# end


# end
