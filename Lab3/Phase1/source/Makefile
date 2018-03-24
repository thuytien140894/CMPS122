LIBS = -lssl -lcrypto
CFLAGS = -Wall
CC = gcc

SRC=$(wildcard *.c)

decrypt: decrypt.o crypto.o
	$(CC) $(CFLAGS) -o decrypt decrypt.o crypto.o $(LIBS)

decrypt.o: decrypt.c crypto.h
	$(CC) $(CFLAGS) -c decrypt.c 

crypto.o: crypto.c crypto.h
	$(CC) $(CFLAGS) -c crypto.c 

clean:
	rm -f decrypt *.o