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

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd);

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds);

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at path FNAME without exceeding 
 * the time limit of 15 minutes.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds);

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD withoiut using more than MAXCPU
 * percent of any processor and exceeding the time limit of 60 seconds. 
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu);
