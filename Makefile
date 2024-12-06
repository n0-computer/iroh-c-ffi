CC = cc
CFLAGS = -Wall -g
LDFLAGS = -L ./target/debug -l iroh_c_ffi -lSystem -lc -lm

all: main multi-thread-client multi-thread-server single-thread-server
main: main.o
main.o: main.c

multi-thread-client: multi-thread-client.o
multi-thread-client.o: multi-thread-client.c
single-thread-server: single-thread-server.o
single-thread-server.o: single-thread-server.c
multi-thread-server: multi-thread-server.o
multi-thread-server.o: multi-thread-server.c

clean:
	rm -f main main.o multi-thread-client.o multi-thread-client multi-thread-server.o multi-thread-server single-thread-server.o single-thread-server
