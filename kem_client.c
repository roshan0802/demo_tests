#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <oqs/oqs.h>

#define PORT 5555

#include <openssl/sha.h>
#include <openssl/evp.h>

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
int aes_gcm_decrypt(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key,const uint8_t *iv,const uint8_t *tag,uint8_t *plaintext)
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
    int sock;
    struct sockaddr_in server_addr;

    const char *kem_name = "ML-KEM-512";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    if (!kem) {
        printf("KEM init failed\n");
        return 1;
    }

    size_t pk_len = kem->length_public_key;
    size_t ct_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;

    uint8_t *pk = malloc(pk_len);
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);

    if (!pk || !ct || !ss) {
        printf("Memory allocation failed\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    if(sock == -1)
    {
        perror("socket");
        return 1;
    }


    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    //inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("connect");
        return 1;
    }

    /* Receive public key */
    recv(sock, pk, pk_len, MSG_WAITALL);

    /* Encapsulation */
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
        printf("Encapsulation failed\n");
        return 1;
    }

    /* Send ciphertext */
    send(sock, ct, ct_len, 0);

    printf("Client derived shared secret (%zu bytes)\n", ss_len);


    uint8_t aes_key[32];
    uint8_t iv[12];
    uint8_t tag[16];
    uint8_t ciphertext[128];

    const uint8_t message[] = "Secure N3 user-plane data";
    size_t msg_len = strlen((const char *)message);

/* Derive AES key */
    derive_aes_key(ss, ss_len, aes_key);

/* Generate IV */
    OQS_randombytes(iv, sizeof(iv));

/* Encrypt */
    int ct_len1 = aes_gcm_encrypt(message, msg_len,
                             aes_key, iv,
                             ciphertext, tag);

uint32_t net_ct_len = htonl(ct_len1);

/* Send IV */
send(sock, iv, sizeof(iv), 0);

/* Send ciphertext length */
send(sock, &net_ct_len, sizeof(net_ct_len), 0);

/* Send ciphertext */
send(sock, ciphertext, ct_len1, 0);

/* Send authentication tag */
send(sock, tag, sizeof(tag), 0);


    close(sock);

    free(pk);
    free(ct);
    free(ss);
    OQS_KEM_free(kem);

    return 0;
}
