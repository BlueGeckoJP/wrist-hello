CC = gcc
AR = ar

CFLAGS = -Wall -Wextra -O2 -std=c11 -fPIC -MMD -MP

TARGET = libcommon.a

SRCS = common.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(AR) rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPS)
