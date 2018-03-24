/**
 * This program defines the three historic ciphers: Caesar, Vigenere, and Polybius Square.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#include "utils.h" 
#include "cipher.h"

char **alphabet_square;

/**
 * Recursively find the Vigenere key that encrypts the given cruzid.
 */
static int try(int counter, int keylen, char *key, const char *message, char *new_message, char *cruzid) {
    if (counter == keylen) {
        new_message[strlen(message)] = '\0';
        if (strcmp(new_message, cruzid) == 0) {
            key[keylen] = '\0'; 
            return TRUE;
        }

        return FALSE;
    }

    char start_letter;
    int index;
    for (int i = 0; i < ALPHABETLEN; i++) {
        key[counter] = i + 'a';
        for (int j = counter; j < strlen(message); j += keylen) {
            if (isalpha(message[j])) {
                start_letter = islower(message[j]) ? 'a' : 'A';
                index = message[j] - start_letter;
                new_message[j] = start_letter + ((index - i + ALPHABETLEN) % ALPHABETLEN);
            } else {
                new_message[j] = message[j];
            }
        }

        if (try(counter + 1, keylen, key, message, new_message, cruzid)) 
            return TRUE;
    }

    return FALSE;
}

/**
 * Find the Vigenere key.
 */
char *find_vigenere_key(int keylen, const char *ciphertext, char *plaintext) {
    char new_message[strlen(ciphertext) + 1];
    char *key = (char *) malloc(keylen + 1);
    strncpy(new_message, ciphertext, strlen(ciphertext));
    if (try(0, keylen, key, ciphertext, new_message, plaintext))
        return key;

    return "Not found";
}

/**
 * Decipher a message encrypted with a Vigenere cipher.
 */
void decipher_vigenere(char *key, const char *message, char *plaintext) {
    char new_message[strlen(message) + 1], start_letter;
    bzero(new_message, strlen(message) + 1);
    int mesglen = strlen(message); 
    strncpy(new_message, message, mesglen);
    int index, offset;
    int pos = 0;

    // skip the message till the first letter is encountered
    while (!isalpha(*message)) {
        new_message[pos++] = *message++;
    }

    for (int i = 0; i < strlen(key); i++) {
        offset = key[i] - 'a';
        for (int j = i; j < strlen(message); j += strlen(key)) {
            if (isalpha(message[j])) {
                start_letter = islower(message[j]) ? 'a' : 'A';
                index = message[j] - start_letter;
                new_message[pos + j] = start_letter + ((index - offset + ALPHABETLEN) % ALPHABETLEN);
            } else {
                new_message[pos + j] = message[j];
            }
        }
    }

    if (strstr(new_message, "tithho") != NULL) {
        strcpy(plaintext, new_message);
        printf("Key %s:\n", key);
        printf("%s\n", new_message);
        fflush(stdout);
    }
}

/**
 * Generate the Polybius alphabet grid.
 */
void generate_polybius_square(char *alphabet) {
    alphabet_square = (char **) malloc(sizeof (char *) * 5);
    for (int i = 0; i < POLYBIUS_SIZE; i++) {
        alphabet_square[i] = (char *) malloc(1);
    }

    int counter = 0;
    for (int i = 0; i < POLYBIUS_SIZE; i++) {
        for (int j = 0; j < POLYBIUS_SIZE; j++) {
            alphabet_square[i][j] = alphabet[counter++];
        }
    }
}

/**
 * Decipher a message encrypted with a Polybius Square cipher.
 */
void decipher_polybius_square(const char *message, char *plaintext) {
    char new_message[strlen(message) + 1];
    bzero(new_message, strlen(message) + 1);
    int row, col;
    int index = 0;
    for (int i = 0; i < strlen(message); i += 2) {
        if (isdigit(message[i]) && isdigit(message[i + 1])) {
            row = message[i] - '0' - 1;
            col = message[i + 1] - '0' - 1;
            new_message[index++] = alphabet_square[row][col];
        } else {
            new_message[index++] = message[i + 1];
        }
    }

    if (strstr(new_message, "tithho") != NULL) {
        strcpy(plaintext, new_message);
        printf("%s\n", new_message);
        fflush(stdout);
    }
}

/**
 * Decipher a message encrypted with a Caesar cipher.
 */
int decipher_caesar(const char *message, int rotation, char *plaintext) {
    char new_message[strlen(message) + 1];
    bzero(new_message, strlen(message) + 1);
    int index;
    char start_letter;
    for (int i = 0; i < strlen(message); i++) {
        if (isalpha(message[i])) {
            start_letter = islower(message[i]) ? 'a' : 'A';
            index = message[i] - start_letter;
            new_message[i] = start_letter + ((index + rotation) % ALPHABETLEN);
        } else {
            new_message[i] = message[i];
        }
    }

    if (strstr(new_message, "tithho") != NULL) {
        strcpy(plaintext, new_message);
        printf("Rotation %d: \n %s\n", rotation, new_message);
        fflush(stdout);
        return TRUE;
    }

    return FALSE;
}

void start_permute(char *start_alphabet, char *alphabet, char *permutation) {
    if (permutation[0] != '-') {
        permute(alphabet, permutation, 1);
    } else {
        for (int i = 0; i < strlen(start_alphabet); i++) {
            if (start_alphabet[i] != '-') {
                permutation[0] = start_alphabet[i];
                alphabet[i] = '-';
                permute(alphabet, permutation, 1);
                alphabet[i] = start_alphabet[i];
            }
        }
    }
}

void permute(char *alphabet, char *permutation, int counter) {
    if (counter == strlen(alphabet)) {
        printf("%s\n", permutation);
        return;
    }

    if (permutation[counter] != '-') {
        permute(alphabet, permutation, counter + 1);
    } else {
        for (int i = 0; i < strlen(alphabet); i++) { 
            if (alphabet[i] != '-') {
                char c = alphabet[i];
                alphabet[i] = '-';
                permutation[counter] = c;
                permute(alphabet, permutation, counter + 1);
                alphabet[i] = c;
            }
        }

        permutation[counter] = '-';
    }
}

void fix_permutation(const char *id, const char *ciphertext, char *permutation) {
    int row, col, index;
    int counter = 0;
    for (int i = 0; i < strlen(ciphertext); i += 2) {
        row = ciphertext[i] - '0' - 1;
        col = ciphertext[i + 1] - '0' - 1;
        index = row * 5 + col;
        permutation[index] = id[counter++];
    }

    printf("%s\n", permutation);
}