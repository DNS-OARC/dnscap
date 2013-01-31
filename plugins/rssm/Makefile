CFLAGS=-Wall -g -fPIC

all: rssm.so

rssm.so: rssm.o hashtbl.o
	gcc -g -shared -o $@ rssm.o hashtbl.o

clean:
	rm -f hashtbl.o
	rm -f rssm.o
	rm -f rssm.so
