CC=musl-gcc
CFLAGS+=-g3 -Og

main: main.o
	$(CC) $(CFLAGS) -Wl,--gc-sections -static $< -o main

.PHONY: all
all: main

.PHONY: clean
clean:
	rm -f main main.o
