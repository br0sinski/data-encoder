CC=gcc
CFLAGS=-Wall -Wextra -O2
ifeq ($(OS),Windows_NT)
	EXE=.exe
	RM=del /Q
	LDFLAGS=
	RUN_TESTS=run_tests.exe
else
	EXE=
	RM=rm -f
	LDFLAGS=-lcrypto
	RUN_TESTS=./run_tests
endif

SRCS=main.c utils/crypto.c utils/random.c
OBJS=$(SRCS:.c=.o)
TEST_SRCS=tests/crypto_test.c utils/crypto.c utils/random.c
TEST_OBJS=$(TEST_SRCS:.c=.o)

all: encoder$(EXE)

encoder$(EXE): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

test: $(TEST_OBJS)
	$(CC) $(TEST_OBJS) -o run_tests$(EXE) $(LDFLAGS)
	$(RUN_TESTS)

clean:
	-$(RM) $(OBJS) $(TEST_OBJS) encoder$(EXE) run_tests$(EXE)