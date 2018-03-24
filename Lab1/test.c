/* 
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without 
 * the written permission of the copyright holder.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <crypt.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/time.h>

#include "crack.h"

#define MAX(a,b) (((a)>(b))?(a):(b))

#define CRYPTLEN 13
#define PWFILE "passwd"
#define MAXCPU 15
#define SPEEDYMINS 15 

typedef struct user_t {
    char uname[16];
    char passwd[16];
    char crypt[CRYPTLEN + 1];
}
User;

static int pwlen = -1;
static User **users;
static int numUsers;

static sem_t sema;
static bool finished;
static bool passed;
static float maxCpu;

/**
 * Returns the number of lines in the file at path
 * FNAME if it exists and can be read, -1 otherwise.
 * 
 * https://stackoverflow.com/questions/12733105
 */
int linesInFile(char *fname) {
    FILE *fp = fopen(fname, "r");
    int lines = -1;
    if (fp) {
        lines = 0;
        while (!feof(fp)) {
            if (fgetc(fp) == '\n') {
                lines++;
            }   
        }
        fclose(fp);
    }
    return lines;
}

static void getUsers(char *fname) {
    numUsers = linesInFile(fname);
    users = malloc(numUsers * sizeof (User*));
    for (int i = 0; i < numUsers; i++)
        users[i] = malloc(sizeof (User));

    char line[64];
    FILE *fin = fopen(fname, "r");
    for (int i = 0; fgets(line, 64, fin) != NULL; i++) {
        sprintf(users[i]->uname, "%s", strtok(line, ":"));
        sprintf(users[i]->passwd, "%s", strtok(strtok(NULL, ":"), "\n"));
        if ((int) strlen(users[i]->passwd) != pwlen) {
            printf("ERROR: supplied passwd length != %d ( '%s' length %d )\n",
                    pwlen, users[i]->passwd, (int) strlen(users[i]->passwd));
            exit(-1);
        }
    }
    fclose(fin);

    FILE *fout = fopen(PWFILE, "w");
    char salt[2 + 1] = {0};
    for (int i = 0; i < numUsers; i++) {
        strncpy(salt, users[i]->uname, 2);
        sprintf(users[i]->crypt, "%s", crypt(users[i]->passwd, salt));
        fprintf(fout, "%s:%s:%s:/home/%s:/bin/sh\n",
                users[i]->uname, users[i]->crypt, users[i]->uname, users[i]->uname);
    }
    fclose(fout);
}

static bool testMultiple() {
    printf("CrackMultiple...\n");
    fflush(stdout);

    struct timeval start;
    gettimeofday(&start, NULL);

    char **passwds = malloc(numUsers * sizeof (char*));
    for (int i = 0; i < numUsers; i++)
        passwds[i] = malloc((pwlen + 1) * sizeof (char));

    crackMultiple(PWFILE, pwlen, passwds);
    int correct = 0;
    for (int i = 0; i < numUsers; i++) {
        for (int j = 0; j < numUsers; j++) {
            if (strcmp(passwds[i], users[j]->passwd) == 0) {
                printf("Cracked: %s\n", passwds[i]);
                correct++;
                break;
            }
        }
    }
    free(passwds);

    struct timeval end;
    gettimeofday(&end, NULL);
    int elapsedSecs = (end.tv_sec - start.tv_sec);

    printf("Cracked: %d of %d\n", correct, numUsers);
    printf("Elapsed: %ds\n", elapsedSecs);
    printf("CrackMultiple: %s\n", correct == numUsers ? "PASS" : "FAIL");
    fflush(stdout);

    return correct == numUsers;
}

static bool doTestSpeedy() {
    char **passwds = malloc(numUsers * sizeof (char*));
    for (int i = 0; i < numUsers; i++)
        passwds[i] = malloc((pwlen + 1) * sizeof (char));

    crackSpeedy(PWFILE, pwlen, passwds);
    int correct = 0;
    for (int i = 0; i < numUsers; i++) {
        for (int j = 0; j < numUsers; j++) {
            if (strcmp(passwds[i], users[j]->passwd) == 0) {
                printf("Cracked: %s\n", passwds[i]);
                correct++;
                break;
            }
        }
    }
    free(passwds);

    printf("Cracked: %d of %d\n", correct, numUsers);
    fflush(stdout);

    return correct == numUsers;
}

static bool testSingle() {
    printf("CrackSingle...\n");
    fflush(stdout);

    struct timeval start;
    gettimeofday(&start, NULL);

    char passwd[pwlen + 1];
    memset(passwd, 0, pwlen + 1);
    crackSingle(users[0]->uname, users[0]->crypt, pwlen, passwd);

    struct timeval end;
    gettimeofday(&end, NULL);
    int elapsedSecs = (end.tv_sec - start.tv_sec);
    bool passed = strcmp(passwd, users[0]->passwd) == 0;

    if (passed)
        printf("Cracked: %s\n", passwd);
    printf("Elapsed: %ds\n", elapsedSecs);
    printf("CrackSingle: %s\n", passed ? "PASS" : "FAIL");
    fflush(stdout);

    return passed;
}

static void *speedyThread(void *arg) {
    finished = doTestSpeedy();
    sem_post(&sema);
    return NULL;
}

static void *timerThread(void *arg) {
    int *sleepSeconds = (int *) arg;
    sleep(*sleepSeconds);
    sem_post(&sema);
    return NULL;
}

static void testSpeedy() {
    printf("CrackSpeedy...\n");
    fflush(stdout);

    sem_init(&sema, 0, 0);
    finished = false;

    struct timeval start;
    gettimeofday(&start, NULL);

    int sleepSeconds = SPEEDYMINS * 60;

    pthread_t tids[2];
    pthread_create(&(tids[0]), NULL, &speedyThread, NULL);
    pthread_create(&(tids[1]), NULL, &timerThread, &sleepSeconds);

    sem_wait(&sema);
    sem_destroy(&sema);

    struct timeval end;
    gettimeofday(&end, NULL);
    int elapsedSecs = (end.tv_sec - start.tv_sec);

    printf("Elapsed: %ds\n", elapsedSecs);
    printf("CrackSpeedy: %s\n", elapsedSecs >= 1.0 && finished ? "PASS" : "FAIL");
    fflush(stdout);
}

static void *stealthyThread(void *arg) {
    char passwd[pwlen + 1];
    memset(passwd, 0, pwlen + 1);
    crackStealthy(users[0]->uname, users[0]->crypt, pwlen, passwd, MAXCPU);
    if (strcmp(passwd, users[0]->passwd) == 0) {
        printf("Cracked: %s\n", passwd);
        fflush(stdout);
        passed = true;
    }
    finished = true;
    sem_post(&sema);
    return NULL;
}

static void *monitorThread(void *arg) {
    int *pid = (int *) arg;
    char cmd[128];
    sprintf(cmd, "ps -p %d -o %%cpu | tail -1", *pid);
    float pct;
    while (!finished) {
        sleep(1);
        FILE *fp;
        fp = popen(cmd, "r");
        fscanf(fp, "%f", &pct);
        //printf("CPU %.1f%%\n", pct);
        //fflush(stdout);
        maxCpu = MAX(maxCpu, pct);
        if (pct > MAXCPU) {
            sem_post(&sema);
            break;
        }
    }
    return NULL;
}

static void testStealthy() {
    printf("CrackStealthy...\n");
    fflush(stdout);

    sem_init(&sema, 0, 0);
    finished = false;
    passed = false;
    maxCpu = 0.0;

    struct timeval start;
    gettimeofday(&start, NULL);

    int sleepSeconds = 60;
    int pid = getpid();

    pthread_t tids[3];
    pthread_create(&(tids[0]), NULL, &stealthyThread, NULL);
    pthread_create(&(tids[1]), NULL, &timerThread, &sleepSeconds);
    pthread_create(&(tids[2]), NULL, &monitorThread, (void *) &pid);

    sem_wait(&sema);
    sem_destroy(&sema);

    struct timeval end;
    gettimeofday(&end, NULL);
    int elapsedSecs = (end.tv_sec - start.tv_sec);

    printf("Elapsed: %ds\n", elapsedSecs);
    printf("Max CPU: %.1f%%\n", maxCpu);
    printf("CrackStealthy: %s\n", passed && finished ? "PASS" : "FAIL");
    fflush(stdout);
}

int main(int argc, char *argv[]) {
    char *usage =
            "Usage: test < -single | -multiple | -speedy | -stealthy > <users file> <passwd length>";

    if (argc != 4) {
        printf("%s\n", usage);
        exit(-1);
    }

    bool single = false;
    bool multiple = false;
    bool speedy = false;
    bool stealthy = false;

    if (strcmp(argv[1], "-single") == 0)
        single = true;
    else if (strcmp(argv[1], "-multiple") == 0)
        multiple = true;
    else if (strcmp(argv[1], "-speedy") == 0)
        speedy = true;
    else if (strcmp(argv[1], "-stealthy") == 0)
        stealthy = true;
    else {
        printf("%s ( %s )\n", usage, argv[1]);
        exit(-1);
    }

    if (access(argv[2], F_OK) == -1) {
        printf("ERROR: file %s does not exist\n", argv[2]);
        exit(-1);
    }

    if (atoi(argv[3]) < 1) {
        printf("ERROR: %s is not a valid password length\n", argv[3]);
        exit(-1);
    }

    pwlen = atoi(argv[3]);
    getUsers(argv[2]);

    if (single)
        testSingle();
    else if (speedy)
        testSpeedy();
    else if (multiple)
        testMultiple();
    else if (stealthy)
        testStealthy();
}
