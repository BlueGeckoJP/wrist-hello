CC = gcc

LDFLAGS = -L../common
LIBS = -lcommon

CFLAGS = -Wall -Wextra -O2 -std=c11 -fPIC -MMD -MP -I../common

TARGET = pam-module.so
SRCS = pam-module.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPS)
