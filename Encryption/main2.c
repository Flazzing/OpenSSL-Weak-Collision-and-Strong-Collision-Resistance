#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

/** 
 * 
 * 
 * 
 **/


int main (){

    unsigned char outbuf[1024];
    int outlen, tmplen;

    char *plaintext = "This is a top secret."; 
    char *ciphertext = "8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9";

    char key[100]; // this represent the total number of keys to stored from "word.txt"
    char initial_vector[100]; // (not the ASCII character ‘0’)

    int i; 

  

    /**
     * 
     * Step 1: First get the key from the "word.txt" 
     *        
     * Reminder: 
     *  1 - You are reading a string into a char array. 
     *  2 - Each key is only 16 characters long
     *  3 - space characters (hexadecimal value 0x20) are appended to the end of the word to form a key of 128 bits.
     * 
     * 
    **/

   FILE *file = fopen("words.txt", "r");

   if (file == NULL){
       printf("File is not being found. \n");
       return 1;
   }

   while (fscanf(file, "%s\n", key) != EOF) {
       
        /**
            * 
            * Reminder 2: Each key is only 16 characters long 
            * 
            * Description: Check string length is 16 character long
            * 
        **/

       if (strlen(key) <= 16) {

           /**
            * 
            * Reminder 3: Append space characters (hexadecimal value 0x20)to the end of the word to form a key of 128 bits
            * 
            * Description: Making sure to append " " at the end of the key 
            * 
            **/

           memset(key + strlen(key), ' ', 16 - strlen(key)); // e.g. (input: "abc") -> (output : "abc ")
           key[16] = '\0';
       }

       /**
        * 
        * Step 2: Encrypt the plaintext with the recently read key to get ciphertext
        * 
        * Reference: 
        * 
        * 
        **/

       
       EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
       EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, initial_vector);

       EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, strlen(plaintext)); 
       EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen); 


       outlen += tmplen;

       EVP_CIPHER_CTX_free(ctx);

        /**
        * 
        * Step 3: Store the outbuff (ciphertext) into a variable, so that outbuff (ciphertext) can be compared with given ciphertext for comparison
        * 
        * Reference: 
        *   - https://www.programmersought.com/article/74121219563/ (Reference to get the outbuff to char array)
        * 
        * 
        **/

       unsigned char outbuff_ciphertext[100];
       for (i = 0; i < outlen; i++) {
           sprintf(outbuff_ciphertext + i * 2, "%02x", outbuf[i]);
       }

       outbuff_ciphertext[outlen * 2] = '\0';

       if (strcmp(outbuff_ciphertext, ciphertext) == 0 ) {
           printf("The key is %s \n", key);
       }
       
      
       // end of program
      
   }
 return 0;
}




