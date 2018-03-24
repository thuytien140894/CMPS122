LIBS = -lssl -lcrypto -lpcap -lpthread
CFLAGS = -Wall
CC = gcc

SRC=$(wildcard *.c)

all: decryptor password_agent

password_agent: password_agent.o 
	$(CC) $(CFLAGS) -o password_agent password_agent.o

decryptor: decryptor.o pcap_sniffer.o crypto.o cipher.o
	$(CC) $(CFLAGS) -o decryptor decryptor.o pcap_sniffer.o cipher.o crypto.o $(LIBS)

password_agent.o: password_agent.c
	$(CC) $(CFLAGS) -c password_agent.c

cipher.o: cipher.c
	$(CC) $(CFLAGS) -c cipher.c

decryptor.o: decryptor.c
	$(CC) $(CFLAGS) -c decryptor.c

pcap_sniffer.o: pcap_sniffer.c
	$(CC) $(CFLAGS) -c pcap_sniffer.c

crypto.o: crypto.c
	$(CC) $(CFLAGS) -c crypto.c

clean:
	rm -f decryptor password_agent *.o
