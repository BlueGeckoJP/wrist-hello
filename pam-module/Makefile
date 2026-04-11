CC = gcc

LDFLAGS = -L../common
LIBS = -lcommon

CFLAGS = -Wall -Wextra -O2 -std=c11 -fPIC -MMD -MP -I../common

TARGET = pam-module.so
SRCS = pam-module.c
OBJS = $(SRCS:.c=.o)
DEPS = $(OBJS:.o=.d)

TEST_TARGET = test-pam-module
TEST_SRCS = test-pam-module.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_DEPS = $(TEST_OBJS:.o=.d)

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(LIBS)

$(TEST_TARGET): $(TEST_OBJS) $(TARGET)
	$(CC) -o $@ $(TEST_OBJS) ./$(TARGET) -Wl,-rpath,. $(LDFLAGS) $(LIBS) -lpam

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	./$(TEST_TARGET)

-include $(DEPS)
-include $(TEST_DEPS)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPS)
	rm -f $(TEST_OBJS) $(TEST_TARGET) $(TEST_DEPS)
