/* 
 * This program implements a four-character password cracker using the brute force 
 * approach of going through all the combinations of four-character passwords given the 
 * set of upper and lower case letters, and numeric digits. The goal is find the one 
 * password whose encryption matches with the provided encrypted password. The program 
 * has methods to crack a single password or to crack all the passwords found in an 
 * old-style /etc/passwd formatted file. 
 * 
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without 
 * the written permission of the copyright holder.
 * 
 * Modified by Tien Ho
 * Date: 01/25/2018
 */

#define _GNU_SOURCE // expose crypt_r()
#include <crypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#define LANGUAGELEN    62
#define MAXLINE       400
#define MAXCHAR        30
#define CRYPTLEN       13
#define SALTLEN         2

// data structure to store the parameter values fr o
// crackSingle()
struct crackInput {
    char *username;
    char *cryptPasswd;
    int  pwlen;
    char *passwd;
};

// Character set for a password
static const char language[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; 

// forward declare crackSingle to be used in crackThread()
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd);

/*
 * The method for a thread to crack a crypted password. The argument ARG is assumed to 
 * be of type "struct crackInput".
 */
static void *crackThread(void *arg) {
    struct crackInput *params = (struct crackInput *) arg;
    if (params != NULL) 
        crackSingle(params->username, params->cryptPasswd, params->pwlen, params->passwd);

    return NULL;
}

/*
 * Wait for all the specified threads to terminate. Any calling thread invoking this 
 * method will be suspended.
 */
static void cleanupThreads(pthread_t *threads, int numThreads) {
    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    return;
}

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD. 
 * 
 * crypt_r() is used so that multiple threads do not have to share the same 
 * static memory used by crypt() to store encrypted data. This prevents 
 * race condition and corrupted data.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd) {
    printf("Cracking password for %s.\n", username);
    fflush(stdout);
    
    char testpwd[pwlen + 1];
    char salt[SALTLEN + 1];
    strncpy(salt, username, SALTLEN);
    struct crypt_data cryptloc;
    cryptloc.initialized = 0;
    char *encrypted;

    for (int a = 0; a < LANGUAGELEN; a++) {
        for (int b = 0; b < LANGUAGELEN; b++) {
            for (int c = 0; c < LANGUAGELEN; c++) {
                for (int d = 0; d < LANGUAGELEN; d++) {
                    bzero(testpwd, sizeof(testpwd));
                    testpwd[0] = language[a]; 
                    testpwd[1] = language[b];
                    testpwd[2] = language[c];
                    testpwd[3] = language[d];
                    
                    // the result of crypt_r() is stored in cryptloc, 
                    // and reassign to encrypted. 
                    encrypted = crypt_r(testpwd, salt, &cryptloc);
                    // check if the encrypted password matches with 
                    // the input cryptPasswd.
                    if (strcmp(cryptPasswd, encrypted) == 0) {
                        strncpy(passwd, testpwd, strlen(testpwd));
                        return;
                    }
                }
            }
        }
    }    	
}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds) { 
    char uname[MAXCHAR];
    char cryptpwd[CRYPTLEN + 1];
    char line[MAXLINE];
    FILE *pwdfile = fopen(fname, "r");
    int counter = 0;

    if (pwdfile) {
        while (fgets(line, MAXLINE, pwdfile) != NULL) {
            sprintf(uname, "%s", strtok(line, ":"));
            sprintf(cryptpwd, "%s", strtok(NULL, ":"));
            crackSingle(uname, cryptpwd, pwlen, passwds[counter++]);
        }
    }

    fclose(pwdfile);
    return;
}

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at path FNAME without exceeding 
 * the time limit of 15 minutes. Instead of cracking each user sequentially 
 * as in crackMultiple(), we use threads to process each user separately 
 * and concurrently.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds) { 
    size_t nthreads = sizeof(passwds) / sizeof(*passwds);
    char uname[MAXCHAR];
    char cryptpwd[CRYPTLEN + 1];
    char line[MAXLINE];
    FILE *pwdfile = fopen(fname, "r");
    pthread_t tids[nthreads];
    int counter = 0;
    char **temp = passwds; 

    if (pwdfile) {
        while (fgets(line, MAXLINE, pwdfile) != NULL) {
            sprintf(uname, "%s", strtok(line, ":"));
            sprintf(cryptpwd, "%s", strtok(NULL, ":"));

            // use struct crackInput to store all the necessary arguments for crackSingle()
            struct crackInput *params = (struct crackInput *) malloc(sizeof(struct crackInput));
            bzero(params, sizeof(struct crackInput));
            params->username = malloc(sizeof(uname) * sizeof(char) + 1);
            strncpy(params->username, uname, strlen(uname));
            params->cryptPasswd = malloc(sizeof(cryptpwd) * sizeof(char) + 1);
            strncpy(params->cryptPasswd, cryptpwd, strlen(cryptpwd));
            params->pwlen = pwlen;
            params->passwd = temp[counter];

            // dispatch a thread to crack passwords for each user
            pthread_create(&(tids[counter++]), NULL, &crackThread, params);
        }
    }
     
    cleanupThreads(tids, counter);
    fclose(pwdfile);
    return;
}

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD without using more than MAXCPU
 * percent of any processor and exceeding the time limit of 60 seconds. We 
 * create a child process to crack the password while leaving the 
 * parent process idle most of the time. Since two processes have separate 
 * memory spaces, a shared memory object is created to pass the password 
 * cracked by the child process back to its parent. 
 * 
 * Reference for creating shared memory used by the parent and child processes:
 * https://stackoverflow.com/a/23860740/7542147
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu) { 
    int shared_fd;
    char *shared_mem;
    const char *mem_name= "Cracked Password";
    int mem_size = (pwlen + 1) * sizeof(char);

    // create a shared memory object to store the cracked password
    if ((shared_fd = shm_open(mem_name, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG)) < 0) {
        perror("Cannot open shared memory");
        exit(0);
    }

    // specify the memory size of the shared memory object and map it to the memory
    ftruncate(shared_fd, mem_size);
    shared_mem = (char *) mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (shared_mem == NULL) {
        perror("Cannot map memory");
        exit(0);
    }

    // create a new process to crack the password
    // this process will have a different pid from its parent
    pid_t child = fork();
    if (child == 0) {
        crackSingle(username, cryptPasswd, pwlen, shared_mem);
        exit(0);
    }

    // suspend the parent process until its child process terminates
    int status = 0;
    waitpid(child, &status, 0);

    // retrieve the cracked password from the shared memory and remove 
    // the shared memory object 
    strncpy(passwd, shared_mem, pwlen);
    shm_unlink(mem_name);

    return;
}
