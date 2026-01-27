#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define PORT 5555

/* Derive AES-256 key from KEM shared secret */
void derive_aes_key(const uint8_t *shared_secret,size_t ss_len,uint8_t aes_key[32])
{
    SHA256(shared_secret, ss_len, aes_key);
}

/* AES-256-GCM encryption */
int aes_gcm_encrypt(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key,uint8_t *iv,uint8_t *ciphertext,uint8_t *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/* AES-256-GCM decryption */
int aes_gcm_decrypt(const uint8_t *ciphertext, int ciphertext_len,const uint8_t *key,
                    const uint8_t *iv,const uint8_t *tag,uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) return -1;

    return plaintext_len + len;
}


int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    const char *kem_name = "ML-KEM-512";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) {
        printf("KEM init failed\n");
        return 1;
    }

    size_t pk_len = kem->length_public_key;
    size_t sk_len = kem->length_secret_key;
    size_t ct_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !sk || !ct || !ss) {
        printf("Memory allocation failed\n");
        return 1;
    }

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        printf("Keypair generation failed\n");
        return 1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if(server_fd == -1)
    {
        perror("socket");
        return 0;
    }


    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    addr.sin_port = htons(PORT);

    if(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        perror("bind");
        return 0;
    }
    if(listen(server_fd, 1)== -1)
    {
        perror("listen");
        return 0;
    }

    printf("Server listening on port %d\n", PORT);
    client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);

    if(client_fd == -1)
    {
        perror("accept");
        return 0;
    }

    /* Send public key */
    send(client_fd, pk, pk_len, 0);

    /* Receive ciphertext */
    recv(client_fd, ct, ct_len, MSG_WAITALL);

    /* Decapsulation */
    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) {
        printf("Decapsulation failed\n");
        return 1;
    }

    printf("Server derived shared secret (%zu bytes)\n", ss_len);

    uint8_t aes_key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t ciphertext[128];
    uint8_t plaintext[128];

/* Derive AES key */
    derive_aes_key(ss, ss_len, aes_key);
uint32_t net_ct_len;

/* Receive IV */
recv(client_fd, iv, sizeof(iv), MSG_WAITALL);

/* Receive ciphertext length */
recv(client_fd, &net_ct_len, sizeof(net_ct_len), MSG_WAITALL);
int ct_len1 = ntohl(net_ct_len);

/* Receive exact ciphertext */
recv(client_fd, ciphertext, ct_len1, MSG_WAITALL);

/* Receive authentication tag */
recv(client_fd, tag, sizeof(tag), MSG_WAITALL);

/* Decrypt */
    int pt_len = aes_gcm_decrypt(ciphertext, ct_len1,
                             aes_key, iv, tag,
                             plaintext);

    if (pt_len < 0) {
    printf("Decryption failed or data tampered\n");
    return 1;
    }

    plaintext[pt_len] = '\0';
    printf("Decrypted message: %s\n", plaintext);

    close(client_fd);
    close(server_fd);

    free(pk);
    free(sk);
    free(ct);
    free(ss);
    OQS_KEM_free(kem);

    return 0;
}
