CC 			= gcc
CFLAGS		= -Wall -g -static-pie
CAPSTONE 	= -lcapstone

sdb : sdb.c
	$(CC) $(CFLAGS) -o $@ $^ $(CAPSTONE)

hello : sdb
	./sdb ./hello

hello64 : sdb
	./sdb ./hello64

guess : sdb
	./sdb ./guess

test : sdb t.c
	$(CC) -nostdlib -nostdinc -no-pie -o test t.c
	./sdb ./test

clear : 
	rm sdb