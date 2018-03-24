/**
 * Header file used by all the files.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#define MAXLINE          4096
#define MAXCHAR           100
#define FALSE               0
#define TRUE                1
#define KEYSIZE            32
#define CRYPTPASSWDLEN     13
#define PASSWDLEN           6
#define IVLEN              32 
#define MESSAGELEN          6    //4
#define NUM_CIPHER          3    //1

#define LISTEN_IPADDR "128.114.59.29"
#define LISTEN_PORT              9990

struct ciphertext {
    unsigned char *content;
    int len;
};

struct message_info {
    char cryptpasswd[CRYPTPASSWDLEN + 1];
    char passwd[PASSWDLEN + 1];
    char keyfd[MAXCHAR];
    char iv[IVLEN + 1];
    struct ciphertext **ciphertexts;
    char **plaintext;
};