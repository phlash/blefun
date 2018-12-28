# Build a Bluetooth LE test program
#
all: build build/blefun

clean:
	rm -rf build

build:
	mkdir -p $@

build/blefun: build/blefun.o
	gcc -o $@ $< -lbluetooth

build/blefun.o: blefun.c
	gcc -c -o $@ $<
