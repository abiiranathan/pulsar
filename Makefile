CC=gcc
CFLAGS=-Wall -Werror -Wextra -pedantic -O3 -std=c23 -D_GNU_SOURCE
LDFLAGS=
TARGET=server
SRC=server.c

$(TARGET): $(SRC)
	$(CC) $(SRC) $(CFLAGS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -rf $(TARGET) perf.data*

.PHONY: $(TARGET) clean