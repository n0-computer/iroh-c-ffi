CC = cc
CFLAGS = -Wall -g
LDFLAGS = -L ./target/debug -l iroh_net_ffi -lSystem -lc -lm

all: main
main: main.o
main.o: main.c

clean:
	rm -f main main.o
