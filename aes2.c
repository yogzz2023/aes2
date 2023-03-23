#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
//key
const static unsigned char key[] = "0123456789ABCDEF0123456789ABC0123456789ABCDEF0123456789ABCDEF";
//iv
const static unsigned char iv[] = "0123456789ABCDEF0123456789ABCDEF";

int encrypt_file(const char *input_file, const char *output_file)
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, 1024, in)) > 0) {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        -1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

int decrypt_file(const char *input_file, const char *output_file) 
{
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    if (!in || !out) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
 int inlen, outlen;

    while ((inlen = fread(inbuf, 1, 1024, in)) > 0) {
        if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen)) {
            return -1;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (!EVP_DecryptFinal_ex(ctx, outbuf, &outlen)) {
        return -1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 0;
}

int main()
{
    const char *input_file = "Screencast from Thursday 23 March 2023 10:35:58  IST.webm";
    const char *encrypted_file = "sample_encrypted.txt";
    const char *decrypted_file = "111Screencast from Thursday 23 March 2023 10:35:58  IST.webm";

    if (encrypt_file(input_file, encrypted_file) == 0) {
        printf("File encrypted successfully.\n");
    } else {
        printf("Encryption failed.\n");
    }

    if (decrypt_file(encrypted_file, decrypted_file) == 0) {
        printf("File decrypted successfully.\n");
    } else {
        printf("Decryption failed.\n");
    }

    return 0;
}