CFLAGS=-Wall -g -fPIC

all: pcapdump.so

pcapdump.so: pcapdump.o
	gcc -g -shared -o $@ pcapdump.o

clean:
	rm -f pcapdump.o
	rm -f pcapdump.so
