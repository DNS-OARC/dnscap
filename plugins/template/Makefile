CFLAGS=-Wall -g -fPIC

all: template.so

template.so: template.o
	gcc -g -shared -o $@ template.o

clean:
	rm -f template.o
	rm -f template.so
