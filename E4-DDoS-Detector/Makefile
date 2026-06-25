.PHONY: all clean

all: program.bpf.o

program.bpf.o: program.bpf.c
	clang -O2 -g -target bpf -c program.bpf.c -o program.bpf.o

clean:
	rm -f program.bpf.o
