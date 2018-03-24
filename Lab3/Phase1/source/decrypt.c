#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto.h"

#define MAXLINE 4096
#define KEYSIZE 32
#define FALSE   0
#define TRUE    1

unsigned char plaintext[MAXLINE], ciphertext[MAXLINE];
char keyblob[MAXLINE], iv[MAXLINE];
int ciphertext_len;

void nextkey(char *key, int startindex) {   
    bzero(key, KEYSIZE + 1);
    strncpy(key, keyblob + startindex, KEYSIZE);
}

void recordmessage() {
    FILE *messagefd = fopen("message.txt", "w");
    if (messagefd) {
        fputs((char *) plaintext, messagefd);
    }

    return;
}

void decryptmessage() {
    int trials = strlen((char *) keyblob) - KEYSIZE + 1;
    char key[KEYSIZE];
    int plaintext_len;
    int finished = FALSE;
    for (int i = 0; i < trials && !finished; i++) {
        nextkey(key, i);
        bzero(plaintext, MAXLINE);
        plaintext_len = decrypt((unsigned char *) ciphertext, ciphertext_len, (unsigned char *) key, (unsigned char *) iv, plaintext);
        if (plaintext_len != -1 && plaintext_len != (ciphertext_len - 1)) {
            printf("Key %d: %s\n", i, key);
            printf("Plaintext: %s\n", plaintext);
            recordmessage();
            fflush(stdout);
            finished = TRUE;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: ./decrypt <ciphertext> <key> <iv> \n");
        exit(0);
    }

    FILE *cipherfd = fopen(argv[1], "rb");
    if (cipherfd) { 
        bzero(ciphertext, MAXLINE);
        ciphertext_len = fread(ciphertext, 1, MAXLINE, cipherfd);
        fclose(cipherfd);
    }
    BIO_dump_fp (stdout, (const char *) ciphertext, ciphertext_len);

    FILE *keyfd = fopen(argv[2], "r");
    if (keyfd) {
        if (fscanf(keyfd, "%s", keyblob) == 1) {
            fclose(keyfd);
        }
    }

    FILE *ivfd = fopen(argv[3], "r");
    if (ivfd) {
        if (fscanf(ivfd, "%s", iv) == 1) {
            fclose(ivfd);
        }
    }

    decryptmessage();
}

