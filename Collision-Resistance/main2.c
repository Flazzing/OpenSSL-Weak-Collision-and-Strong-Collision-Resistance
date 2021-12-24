    #include <stdio.h>
    #include <stdlib.h>
    #include <time.h>
    #include <string.h>
    #include <openssl/evp.h>

    /**
     * 
     * Function: randomString()
     * 
     * Description: Generate a random string 
     * 
     * Argument: 
     *     - dest : Char pointer variable to store randomly generated string
     *     - length: The length of the random string to be generated
     * 
     * Reference: 
     *     - https://stackoverflow.com/questions/15767691/whats-the-c-library-function-to-generate-random-string
     * 
     **/

    void randomString(char *dest, size_t length){
        char charset[] = "0123456789"
                        "abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        while (length-- > 0) {
            size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
            *dest++ = charset[index];
        }
        *dest = '\0';
    }


    /**
     * 
     * Function: weakCollission()
     * 
     * Description: Given an input to a hash function, it is computationally infeasible to find another input such that both inputs lead to the same hash output 
     * 
     * Arguments: 
     * 
     * 
     * 
     * **/

    void weakCollision(FILE *weak, int argc, char *argv[]){


        // step 1: Get input 1 with hash function 

        // declaration for input 1
        char input1[40];
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        unsigned char md_value1[EVP_MAX_MD_SIZE];
        int md_len, i;

        // declaration for input 2
        char input2[40];
        EVP_MD_CTX *mdctx2;
        unsigned char md_value2[EVP_MAX_MD_SIZE];
        int md_len2, i2;

        // store hash value

        unsigned char cryptohex1[50]; 
        unsigned char cryptohex2[50]; 

        
        randomString(input1, 10);

        OpenSSL_add_all_algorithms();

        if (argv[1] == NULL) {
            printf("Usage: mdtest digestname\n");
            exit(1);
        }
        
        md = EVP_get_digestbyname(argv[1]);
        if(!md) {
            printf("Unknown message digest %s\n", argv[1]);
            exit(1);
        }

        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, input1, strlen(input1));
        EVP_DigestFinal_ex(mdctx, md_value1, &md_len);
        EVP_MD_CTX_destroy(mdctx);

        for (i = 0; i < md_len; i++) { 
                // Format the encryption result ciphertext into cryptohex in hexadecimal format, and format the ciphertext output to cryptohex.
                sprintf(cryptohex1+i*2,"%02x", md_value1[i]); 
        } 

        cryptohex1[md_len*2] = '\0'; 

        printf("String Value : %s\n", input1);

        // printf("Hash Value   : ");
        // for (i = 0; i < md_len; i++)
        //     printf("%02x", md_value1[i]);
        
        // printf("\n");
        printf("Hash Value   : %s \n", cryptohex1);

        // step 2: get input 2 with hash function and repeat to get similar hash output of input1

        int total = 0;
        printf("Weak Collision is running\n");
        while (1) {
            randomString(input2, 10);

            if(strcmp(input2, input1) == 0){
                randomString(input2, 10);
            }

            mdctx2 = EVP_MD_CTX_create();
            EVP_DigestInit_ex(mdctx2, md, NULL);
            EVP_DigestUpdate(mdctx2, input2, strlen(input2));
            EVP_DigestFinal_ex(mdctx2, md_value2, &md_len2);
            EVP_MD_CTX_destroy(mdctx2);

            for (i = 0; i < md_len2; i++) { 
                // Format the encryption result ciphertext into cryptohex in hexadecimal format, and format the ciphertext output to cryptohex.
                sprintf(cryptohex2+i*2,"%02x", md_value2[i]);
                } 
                
                // cryptohex2[md_len2*2] = '\0'; 
                // printf("Digest is: ");
                // for (i = 0; i < md_len2; i++)
                // printf("%02x", md_value2[i]);
                // printf("\n");


            if (memcmp(cryptohex2, cryptohex1, 3) == 0) {       
                printf("String Value 2 : %s\n", input2);  
                printf("Input 1: %s \n", cryptohex1);
                printf("Input 2: %s \n", cryptohex2);
                printf("length: %d \n", strlen(md_value2));
                printf("Total attemp: %d\n", total);
                fprintf(weak, "%d\n", total);
                break;
            }
            else {
                total++;
            }
        }
    }

    /**
     * 
     * Function: strongCollission()
     * 
     * Description: It is computationally infeasible to find two different inputs to a hash function that will lead to the same hash output 
     * 
     * Arguments: 
     * 
     * 
     * 
     * **/

    void strongCollision(FILE *strong, int argc, char *argv[]){

        printf("Strong Collision is running\n");

        int total = 0;

        unsigned char input_table[6][40];
        unsigned char hash_value_table[6][7];
        int table_i = 0;
        int table_x = 0;
        int isFilled = 0; // 0 = false; 1 = true; table is filled
        
        
        while (1){

            char input1[40];
            EVP_MD_CTX *mdctx;
            const EVP_MD *md;
            unsigned char md_value1[EVP_MAX_MD_SIZE];
            int md_len, i;

            // declaration for input 2
            char input2[40];
            EVP_MD_CTX *mdctx2;
            unsigned char md_value2[EVP_MAX_MD_SIZE];
            int md_len2, i2;


            unsigned char cryptohex1[50]; 
            unsigned char cryptohex2[50]; 
            
            
            randomString(input1, 5);
            randomString(input2, 5);

            if(strcmp(input1, input2) == 0) {
                randomString(input2, 5);
            }

            

            for (table_x = 0; table_x < 6; table_x++) {
                if (strcmp(input1, input_table[table_x]) == 0) {
                    randomString(input1, 5);
                }

                if (strcmp(input2, input_table[table_x]) == 0) {
                    randomString(input2, 5);
                }
            }

            OpenSSL_add_all_algorithms();

            if (argv[1] == NULL) {
                printf("Usage: mdtest digestname\n");
                exit(1);
            }
        
            md = EVP_get_digestbyname(argv[1]);
            if(!md) {
                printf("Unknown message digest %s\n", argv[1]);
                exit(1);
            }

            // hash value for input 1

            mdctx = EVP_MD_CTX_create();
            EVP_DigestInit_ex(mdctx, md, NULL);
            EVP_DigestUpdate(mdctx, input1, strlen(input1));
            EVP_DigestFinal_ex(mdctx, md_value1, &md_len);
            EVP_MD_CTX_destroy(mdctx);

            for (i = 0; i < md_len; i++) { 
                // Format the encryption result ciphertext into cryptohex in hexadecimal format, and format the ciphertext output to cryptohex.
                sprintf(cryptohex1+i*2,"%02x", md_value1[i]); 
            } 

            // hash value for input 2

            mdctx2 = EVP_MD_CTX_create();
            EVP_DigestInit_ex(mdctx2, md, NULL);
            EVP_DigestUpdate(mdctx2, input2, strlen(input2));
            EVP_DigestFinal_ex(mdctx2, md_value2, &md_len2);
            EVP_MD_CTX_destroy(mdctx2);

            for (i = 0; i < md_len2; i++) { 
                // Format the encryption result ciphertext into cryptohex in hexadecimal format, and format the ciphertext output to cryptohex.
                sprintf(cryptohex2+i*2,"%02x", md_value2[i]);
                } 

                table_i += 2;

                if ((table_i % 2 == 0) && (table_i <= 6) && (isFilled== 0)){
                    strcpy(input_table[table_i - 2], input1); 
                    strcpy(input_table[table_i - 1], input2);
                    strcpy(hash_value_table[table_i - 2], cryptohex1); 
                    strcpy(hash_value_table[table_i - 1], cryptohex2); 
                }

                 if ((table_i % 2 == 0) && (table_i <= 6) && (isFilled== 1)){

                      for (table_x = 0; table_x < 6; table_x++) {

                        if ((memcmp(hash_value_table[table_x], cryptohex1, 3) == 0) && (strcmp(input1, input_table[table_x]) != 0)) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input1 );
                            printf("Hash value: %s\n", cryptohex1);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                        if ((memcmp(hash_value_table[table_x], cryptohex2, 3) == 0) && (strcmp(input2, input_table[table_x] ) != 0)) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value 1: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input2);
                            printf("Hash value 2: %s\n", cryptohex2);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                    }

                    strcpy(input_table[table_i - 2], input1); 
                    strcpy(input_table[table_i - 1], input2);
                    strcpy(hash_value_table[table_i - 2], cryptohex1); 
                    strcpy(hash_value_table[table_i - 1], cryptohex2); 
                }

                // printf("Input 1: %s\n", input1);
                // printf("Hash 1: %s\n", cryptohex1);
                
                // printf("Input 2: %s\n", input2);
                // printf("Hash 2: %s\n", cryptohex2);


                // printf("\nIteration: %d\n\n", table_i);
                
                // printf("Checker input 1: %s\n", input_table[table_i - 2]);
                // printf("Checker Hash 1: %s\n", hash_value_table[table_i - 2]);

                // printf("Checker input 2: %s\n", input_table[table_i - 1]);
                // printf("Checker Hash 2: %s\n", hash_value_table[table_i - 1]);

                if (isFilled == 1 && table_i <= 6){
                    for (table_x = 0; table_x < 6; table_x++) {

                        if ((memcmp(hash_value_table[table_x], cryptohex1, 3) == 0) && (strcmp(input1, input_table[table_x]) != 0)) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input1 );
                            printf("Hash value: %s\n", cryptohex1);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                        if ((memcmp(hash_value_table[table_x], cryptohex2, 3) == 0) && (strcmp(input2, input_table[table_x] ) != 0)) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value 1: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input2);
                            printf("Hash value 2: %s\n", cryptohex2);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                    }
                }

                if (table_i > 6) {

                    for (table_x = 0; table_x < 6; table_x++) {

                        if ((memcmp(hash_value_table[table_x], cryptohex1, 3) == 0) && (strcmp(input1, input_table[table_x]) != 0)) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input1 );
                            printf("Hash value: %s\n", cryptohex1);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                        if ((memcmp(hash_value_table[table_x], cryptohex2, 3) == 0) && (strcmp(input2, input_table[table_x] ) != 0) ) {  
                            printf("Collision Found !\n");
                            printf("Input 1: %s\n", input_table[table_x]);
                            printf("Hash value 1: %s\n", hash_value_table[table_x]);
                            printf("Input 2: %s\n", input2);
                            printf("Hash value 2: %s\n", cryptohex2);
                            printf("Total attempt: %d\n", total);
                            fprintf(strong, "%d\n", total);
                            return;
                        }

                    }

                        table_i = 0;
                        isFilled = 1;
                        strcpy(input_table[2], input1); 
                        strcpy(input_table[3], input2);
                        strcpy(hash_value_table[2], cryptohex1); 
                        strcpy(hash_value_table[3], cryptohex2); 
                }


            if (memcmp(cryptohex2, cryptohex1, 3) == 0) {         
                printf("Input 1: %s \n", cryptohex1);
                printf("Input 2: %s \n", cryptohex2);
                printf("Total attemp: %d\n", total);
                fprintf(strong, "%d\n", total);
                return;
            }
            else {
                total++;
            }

        }
    
    }


    int main(int argc, char *argv[])
    {
        int i = 0;
        int repeat = 100;

        FILE *strong = fopen("strongCol.txt", "w");
        FILE *weak = fopen("weakCol.txt", "w");

       printf("Strong Collision--------\n");

        for (i = 0; i < repeat; i++){
            strongCollision(strong, argc, argv);
        }

        printf("\n\nWeak Collision--------\n");

         for (i = 0; i < repeat; i++){
            weakCollision(weak, argc, argv);
        }
        fclose(strong);
        fclose(weak);

        // for (i = 0; i < repeat; i++) {
        //      strongCollision();
        // }
        

        return 0;
    }