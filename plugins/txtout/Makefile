CFLAGS=-Wall -g -fPIC

all: txtout.so

txtout.so: txtout.o
	gcc -g -shared -o $@ txtout.o

clean:
	rm -f txtout.o
	rm -f txtout.so
