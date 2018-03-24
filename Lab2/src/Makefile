CFLAGS = -Wall
CC = gcc

SRC=$(wildcard *.c)

all: smash findbackdoor

smash: smash.c
	$(CC) -o smash smash.c utils.h $(CFLAGS)

findbackdoor: findbackdoor.c
	$(CC) -o findbackdoor findbackdoor.c utils.h $(CFLAGS)

shell: shell.c
	$(CC) -fno-stack-protector -z execstack -ggdb -static shell.c -o shell $(CFLAGS)

clean:
	rm -f smash findbackdoor serverinfo.txt in.txt