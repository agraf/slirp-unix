CFLAGS := $(shell pkg-config --cflags slirp)
LDFLAGS := $(shell pkg-config --libs slirp)
OBJS := slirp_unix.o

%.o: %.c
	gcc -c -Wall $< -o $@ $(CFLAGS)

slirp_unix: $(OBJS)
	gcc -Wall $(OBJS) -o $@ $(LDFLAGS)
