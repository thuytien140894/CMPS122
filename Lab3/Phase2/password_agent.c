/**
 * This program creates a listening server to receive cracked passwords from NSA.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */ 
#include "utils.h"

#define LISTENQ 70

struct sockaddr_in servaddr;
int connfd, listenfd;
char buff[MAXLINE];

int main (int argc, char **argv) {
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(LISTEN_PORT);

    // intialize the server's ip address
    if (inet_pton(AF_INET, LISTEN_IPADDR, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", LISTEN_IPADDR);
        exit(0);
    }

    // create a listen socket
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        exit(0);
    }

    // bind the server address to the listening socker
    if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("error in binding");
        exit(0);
    }

    if (listen(listenfd, LISTENQ) < 0)
        exit(0);

    printf("Listening on port %d at %s\n", LISTEN_PORT, LISTEN_IPADDR);
    fflush(stdout);    

    // receive connections from NSA
    for ( ; ; ) {
        connfd = accept(listenfd, (struct sockaddr *) NULL, NULL);
        if (connfd < 0) {
            perror("connection failure");
            continue;
        }

        bzero(buff, MAXLINE);
        int recv;
        if ((recv = read(connfd, buff, MAXLINE)) < 0) {
            perror("read error");
            exit(0);
        } else if (recv > 0) {
            printf("%s\n", buff);
        }
        
        close(connfd);
    }
}