/**
 * Copyright (C) 2018 David C. Harrison - All Rights Reserved.
 * You may not use, distribute, or modify this code without
 * the written permission of the copyright holder.
 *
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
 */

/**
 * Encrypt PLAINTEXT of length PLAINTEXT_LEN using the 128-Bit AES key KEY
 * and Input Vector IV, placing the resulting cypher text in CIPHERTEXT, which
 * must be large enough.
 * 
 * Return the number of bytes written into CIPHERTEXT.
 */ 
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);

/**
 * Decrypt CIPHERTEXT of length CIPHERTEXT_LEN using the 128-Bit AES key KEY
 * and Input Vector IV, placing the resulting cypher text in PLAINTEXT, which
 * must be large enough.
 * 
 * Return the number of bytes written into PLAINTEXT.
 */ 
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);

/**
 * Simple demo of how to use the above functions.
 */
void demo(void);
