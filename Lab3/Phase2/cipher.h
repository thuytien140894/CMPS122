/**
 * This program defines the three historic ciphers: Caesar, Vigenere, and Polybius Square.
 * 
 * Name: Tien Thuy Ho
 * Date: 03/09/2018
 */

#define ALPHABETLEN                           26
#define ALPHABET     "abcdefghijklmnopqrstuvwxy"
#define POLYBIUS_SIZE                          5

/**
 * Find the Vigenere key.
 */
char *find_vigenere_key(int keylen, const char *ciphertext, char* plaintext);

/**
 * Decipher a message encrypted with a Vigenere cipher.
 */
void decipher_vigenere(char *key, const char *message, char *plaintext);

/**
 * Decipher a message encrypted with a Polybius Square cipher.
 */
void decipher_polybius_square(const char *message, char *plaintext);

/**
 * Generate the Polybius alphabet grid.
 */
void generate_polybius_square(char *alphabet);

/**
 * Decipher a message encrypted with a Caesar cipher.
 */
int decipher_caesar(const char *message, int rotation, char *plaintext);

void start_permute(char *start_alphabet, char *alphabet, char *permutation);
void permute(char *alphabet, char *permutation, int counter);
void fix_permutation(const char *id, const char *ciphertext, char *permutation);