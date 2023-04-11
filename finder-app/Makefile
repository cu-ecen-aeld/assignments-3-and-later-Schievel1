##
# assignment2-Schievel1
#
# @file
# @version 0.1

CC = $(CROSS_COMPILE)gcc
CFLAGS = -Wall -Werror
SRCS = writer.c
OBJS = $(SRCS:.c=.o) #replace .c file
TARGET = $(SRCS:.c=) #replace .c with nothing"" for eg. writer.c => writer

all: $(TARGET)
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

.c.o:
	$(CC) -c  $(SRCS)

clean:
	rm -f $(TARGET) *.o
