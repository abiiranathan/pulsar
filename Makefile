CC=gcc
CFLAGS=-Wall -Werror -Wextra -pedantic -O3 -std=c23 -D_GNU_SOURCE -fno-builtin -mtune=native -march=native
LDFLAGS=
TARGET=server
SRC=main.c pulsar.c forms.c

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf $(TARGET) perf.data*

.PHONY: $(TARGET) clean