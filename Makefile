CC = cc
CFLAGS = -Wall -g -O0
LDFLAGS = -L ./target/debug -l iroh_c_ffi -lSystem -lc -lm

all: main multi-thread-client multi-thread-server single-thread-server

main: main.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

multi-thread-client: multi-thread-client.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

multi-thread-server: multi-thread-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

single-thread-server: single-thread-server.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic compile rule for .c → .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f main main.o multi-thread-client.o multi-thread-client \
	      multi-thread-server.o multi-thread-server \
	      single-thread-server.o single-thread-server
