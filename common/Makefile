CC = gcc
AR = ar

CFLAGS = -Wall -Wextra -O2 -std=c11 -fPIC

TARGET = libcommon.a

SRCS = common.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
