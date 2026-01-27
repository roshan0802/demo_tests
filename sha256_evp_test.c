#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

int sha256_hash_evp(const unsigned char *data, size_t data_len,
                    unsigned char *hash_out, unsigned int *hash_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return 0;
    }

    /* Initialize digest operation */
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    /* Feed input data */
    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    /* Finalize digest */
    if (EVP_DigestFinal_ex(ctx, hash_out, hash_len) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}
char *getstr()
{
    char *buffer=NULL;
    int i=0;
    do
    {
        /* code */
        buffer=realloc(buffer,(i+1));
        buffer[i]=getchar();
    } while(buffer[i++]!='\n');
    buffer[i]='\0';
    return buffer;
}
int main()
{
    const char *message[3];
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    for(int i=0;i<3;i++)
    {
        message[i]=getstr();
    if (!sha256_hash_evp((const unsigned char *)message[i],
                          strlen(message[i]),
                          hash, &hash_len)) {
        fprintf(stderr, "SHA-256 computation failed\n");
        return 1;
    }


    printf("SHA-256: ");
    for (unsigned int i = 0; i < hash_len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

}
    return 0;
}
