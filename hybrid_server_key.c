/*
 * Threaded hybrid server (per-client):
 * - Uses liboqs Kyber512 (PQC KEM)
 * - Uses OpenSSL ECDH (P-256) for classical secret
 * - Combines classical || pqc via HKDF-SHA256 to derive final 32-byte key
 * - Uses robust full_send/full_recv helpers
 * - No goto-based cleanup: resources are explicitly freed on each error path
 *
 * Build: gcc hybrid_server_key.c -o hybrid_server_key -loqs -lssl -lcrypto -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define SERVER_PORT 5555
#define BUFSIZE 4096

static ssize_t full_send(int fd, const void *buf, size_t len) 
{
    const uint8_t *p = buf;
    size_t left = len;
    /* Loop until all bytes have been sent or an error occurs. */
    while (left > 0) 
    {
        ssize_t s = send(fd, p, left, 0);
        /* On error, retry if interrupted; otherwise return failure. */
        if (s < 0) {
            if (errno == EINTR) 
                continue;
            return -1;
        }
        /* If send returns zero, the connection is closed; propagate EOF. */
        if (s == 0) 
            return 0;
        p += s;
        left -= s;
    }
    return (ssize_t)len;
}

static ssize_t full_recv(int fd, void *buf, size_t len) 
{
    uint8_t *p = buf;
    size_t left = len;
    /* Loop until the requested number of bytes have been received. */
    while (left > 0) 
    {
        ssize_t r = recv(fd, p, left, 0);
        /* Retry on EINTR and propagate other errors. */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        /* A return value of 0 indicates the peer closed the connection. */
        if (r == 0) return 0; /* connection closed */
        p += r;
        left -= r;
    }
    return (ssize_t)len;
}

/* Minimal HKDF-SHA256 (extract with zero salt, expand) */
/* HKDF helpers: separate Extract and Expand so we can perform sequential Extract
 * mixing (recommended for hybrid KEM + ECDH). We provide:
 *  - hkdf_extract(prk_out, ikm, ikm_len, salt, salt_len)
 *  - hkdf_expand(prk, prk_len, info, info_len, out, out_len)
 */
static int hkdf_extract(uint8_t *prk_out, const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len) 
{
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk_out, &prk_len))
        return 0;
    /* prk_len should equal SHA256_DIGEST_LENGTH */
    return (prk_len == SHA256_DIGEST_LENGTH) ? 1 : 0;
}

static int hkdf_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) 
{
    const size_t hash_len = SHA256_DIGEST_LENGTH;
    uint8_t t[SHA256_DIGEST_LENGTH];
    size_t t_len = 0;
    size_t n = (out_len + hash_len - 1) / hash_len;
    if (n == 0 || n > 255) return 0;

    uint8_t *okm = out;
    size_t remaining = out_len;
    for (uint8_t i = 1; i <= n; ++i) 
    {
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) 
            return 0;
        if (HMAC_Init_ex(hctx, prk, (int)prk_len, EVP_sha256(), NULL) != 1) 
        { 
            HMAC_CTX_free(hctx); 
            return 0; 
        }
        if (t_len > 0) 
                HMAC_Update(hctx, t, t_len);
        if (info && info_len > 0) 
            HMAC_Update(hctx, info, info_len);
        uint8_t c = i;
        HMAC_Update(hctx, &c, 1);
        unsigned int len = 0;
        if (HMAC_Final(hctx, t, &len) != 1) 
        { 
            HMAC_CTX_free(hctx); 
            return 0; 
        }
        HMAC_CTX_free(hctx);
        size_t copy_len = (remaining > hash_len) ? hash_len : remaining;
        memcpy(okm, t, copy_len);
        okm += copy_len;
        remaining -= copy_len;
        t_len = len;
    }
    OPENSSL_cleanse(t, sizeof(t));
    return 1;
}

/* Compatibility wrapper: previous code used hkdf_sha256(ikm, ikm_len, info, info_len, out, out_len)
 * which performed HKDF-Extract with zero salt then Expand. Provide the same
 * behavior using the new helpers so existing calls continue to work.
 */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,const uint8_t *info, size_t info_len,uint8_t *out, size_t out_len) 
{
    uint8_t prk[SHA256_DIGEST_LENGTH];
    uint8_t zero_salt[SHA256_DIGEST_LENGTH];
    memset(zero_salt, 0, sizeof(zero_salt));
    if (!hkdf_extract(prk, ikm, ikm_len, zero_salt, sizeof(zero_salt))) 
        return 0;
    int ok = hkdf_expand(prk, SHA256_DIGEST_LENGTH, info, info_len, out, out_len);
    OPENSSL_cleanse(prk, sizeof(prk));
    return ok;
}

/* AES-256-GCM helpers ---------------------------------------------------- */
/* Encrypt plaintext -> ciphertext and tag. Returns ciphertext length on
 * success, -1 on failure. Caller must provide ciphertext_out buffer of at
 * least plaintext_len bytes and tag_out of at least 16 bytes. */
static int aes256gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                            const uint8_t *plaintext, int plaintext_len,
                            uint8_t *ciphertext_out, uint8_t *tag_out) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, clen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) 
        goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) 
        goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) 
        goto err;
    if (plaintext_len > 0) 
    {
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, plaintext_len) != 1) 
            goto err;
        clen = len;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext_out + clen, &len) != 1) 
        goto err;
    clen += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out) != 1) 
        goto err;
    EVP_CIPHER_CTX_free(ctx);
    return clen;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* Decrypt ciphertext with tag -> plaintext. Returns plaintext length on
 * success, -1 on failure (including authentication failure). */
static int aes256gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                            const uint8_t *ciphertext, int ciphertext_len,
                            const uint8_t *tag, uint8_t *plaintext_out) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        return -1;
    int len = 0, plen = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) 
        goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) 
        goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) 
        goto err;
    if (ciphertext_len > 0) 
    {
        if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, ciphertext_len) != 1) 
            goto err;
        plen = len;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1) 
        goto err;
    if (EVP_DecryptFinal_ex(ctx, plaintext_out + plen, &len) != 1) 
        goto err;
    plen += len;
    EVP_CIPHER_CTX_free(ctx);
    return plen;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
/* --- helper functions to make client_thread readable --- */

static int kem_setup(const char *kem_name, OQS_KEM **kem_out,
                     uint8_t **pk_out, uint8_t **sk_out,
                     size_t *pk_len_out, size_t *sk_len_out,
                     size_t *ct_len_out, size_t *ss_len_out) 
{
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    /* Allocate and initialize KEM state for the named algorithm. */
    if (!kem) 
        return 0;

    size_t pk_len = kem->length_public_key;
    size_t sk_len = kem->length_secret_key;
    size_t ct_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;

    uint8_t *pk = malloc(pk_len);
    uint8_t *sk = malloc(sk_len);
    /* Allocate storage for public and secret keys; on failure clean up. */
    if (!pk || !sk) {
        if (pk) free(pk);
        if (sk) free(sk);
        OQS_KEM_free(kem);
        return 0;
    }
    /* Generate the PQC KEM keypair. */
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
        free(pk); free(sk); OQS_KEM_free(kem);
        return 0;
    }
    *kem_out = kem;
    *pk_out = pk; *sk_out = sk;
    *pk_len_out = pk_len; *sk_len_out = sk_len;
    *ct_len_out = ct_len; *ss_len_out = ss_len;
    return 1;
}

static EVP_PKEY *ecdh_generate_and_serialize(unsigned char **out_der, int *out_len) 
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    /* Create new EC key for P-256 and generate the keypair. */
    if (!ec_key) 
        return NULL;
    if (EC_KEY_generate_key(ec_key) != 1) 
    { 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) 
    { 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    /* Assign the EC_KEY to an EVP_PKEY wrapper (ownership transfers). */
    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) 
    { 
        EVP_PKEY_free(pkey); 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    /* Serialize public key to DER for sending to client. */
    unsigned char *der = NULL;
    int der_len = i2d_PUBKEY(pkey, &der);
    if (der_len <= 0) 
    { 
        EVP_PKEY_free(pkey); 
        if (der) OPENSSL_free(der); 
        return NULL; 
    }
    *out_der = der; *out_len = der_len;
    return pkey;
}

static int send_server_kem_and_ec(int client_sock, uint32_t session_id, uint8_t *server_kem_pk, size_t pk_len,
                                   unsigned char *server_ec_pub_der, int server_ec_pub_der_len) 
{
    /* Send session id (network order) first. */
    uint32_t net_sid = htonl(session_id);
    if (full_send(client_sock, &net_sid, sizeof(net_sid)) != (ssize_t)sizeof(net_sid))
        return 0;
    /* Send server's PQC public key (fixed length). */
    if (full_send(client_sock, server_kem_pk, pk_len) != (ssize_t)pk_len) 
        return 0;
    uint32_t net_len = htonl((uint32_t)server_ec_pub_der_len);
    /* Send length-prefixed server EC public key DER. */
    if (full_send(client_sock, &net_len, sizeof(net_len)) != (ssize_t)sizeof(net_len)) 
        return 0;
    if (full_send(client_sock, server_ec_pub_der, server_ec_pub_der_len) != server_ec_pub_der_len) 
        return 0;
    return 1;
}

static int recv_cipher_and_client_ec(int client_sock, uint8_t *ciphertext, size_t ct_len,
                                     unsigned char **client_ec_pub_der_out, uint32_t *client_ec_pub_len_out) 
{
    /* Receive fixed-length ciphertext from client. */
    if (full_recv(client_sock, ciphertext, ct_len) != (ssize_t)ct_len) 
        return 0;
    uint32_t len_net = 0;
    /* Receive 32-bit network-order length for client's EC public key DER. */
    if (full_recv(client_sock, &len_net, sizeof(len_net)) != (ssize_t)sizeof(len_net)) 
        return 0;
    uint32_t len = ntohl(len_net);
    /* Sanity-check the length, allocate buffer and receive the DER bytes. */
    if (len == 0 || len > 10000) 
        return 0;
    unsigned char *der = malloc(len);
    if (!der) 
        return 0;
    if (full_recv(client_sock, der, len) != (ssize_t)len) 
    { 
        free(der); 
        return 0; 
    }
    *client_ec_pub_der_out = der;
    *client_ec_pub_len_out = len;
    return 1;
}

/* New helper: receive a single message framed as: iv(12) || uint32_be(ct_len) || ciphertext || tag(16)
 * Returns 1 on success and fills *pt_out (allocated) and *pt_len_out, else 0.
 */

static int decaps_and_derive(EVP_PKEY *server_ec_key, OQS_KEM *kem, uint8_t *server_kem_sk,
                            uint8_t *ciphertext, unsigned char *client_ec_pub_der, uint32_t client_ec_pub_len,
                            size_t ss_len, uint8_t *out_final_key /* 32 bytes */) 
{
    /* pqc decap */
    /* Allocate buffer for PQC shared secret and decapsulate ciphertext. */
    uint8_t *pqc_shared = malloc(ss_len);
    if (!pqc_shared) 
        return 0;
    if (OQS_KEM_decaps(kem, pqc_shared, ciphertext, server_kem_sk) != OQS_SUCCESS) 
    { 
        free(pqc_shared); 
        return 0; 
    }

    /* reconstruct client pubkey and derive classical */
    const unsigned char *pp = client_ec_pub_der;
    /* Reconstruct client's public key from DER. */
    EVP_PKEY *client_pub = d2i_PUBKEY(NULL, &pp, client_ec_pub_len);
    if (!client_pub) 
    { 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    /* Create a derive context and initialize ECDH derive operation. */
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(server_ec_key, NULL);
    if (!derive_ctx) 
    { 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    /* Initialize derive; fail on any error. */
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    /* Set the peer public key for the derive operation. */
    if (EVP_PKEY_derive_set_peer(derive_ctx, client_pub) <= 0) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    size_t classical_len = 0;
    /* Query length for the derived classical secret. */
    if (EVP_PKEY_derive(derive_ctx, NULL, &classical_len) <= 0) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    /* Allocate buffer for classical shared secret. */
    uint8_t *classical_shared = malloc(classical_len);
    if (!classical_shared) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    /* Derive the classical ECDH shared secret into the allocated buffer. */
    if (EVP_PKEY_derive(derive_ctx, classical_shared, &classical_len) <= 0) 
    { 
        OPENSSL_cleanse(classical_shared, classical_len); 
        free(classical_shared); 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(client_pub); 
        OPENSSL_cleanse(pqc_shared, ss_len); 
        free(pqc_shared); 
        return 0; 
    }
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(client_pub);

    /* Sequential HKDF-Extract mixing (classical then PQC) -> out_final_key (32 bytes)
     * prk1 = HKDF-Extract(zeros, classical_shared)
     * prk2 = HKDF-Extract(prk1, pqc_shared)
     * final = HKDF-Expand(prk2, info)
     */
    const char info[] = "5G-HYBRID-N2-N3";
    uint8_t prk1[SHA256_DIGEST_LENGTH];
    uint8_t prk2[SHA256_DIGEST_LENGTH];
    uint8_t zero_salt[SHA256_DIGEST_LENGTH];
    memset(zero_salt, 0, sizeof(zero_salt));
    int ok = 0;
    if (!hkdf_extract(prk1, classical_shared, classical_len, zero_salt, sizeof(zero_salt))) {
        ok = 0;
        goto derive_cleanup;
    }
    if (!hkdf_extract(prk2, pqc_shared, ss_len, prk1, SHA256_DIGEST_LENGTH)) {
        ok = 0;
        goto derive_cleanup;
    }
    if (!hkdf_expand(prk2, SHA256_DIGEST_LENGTH, (const uint8_t *)info, strlen(info), out_final_key, 32)) {
        ok = 0;
        goto derive_cleanup;
    }
    ok = 1;

derive_cleanup:
    OPENSSL_cleanse(prk1, sizeof(prk1));
    OPENSSL_cleanse(prk2, sizeof(prk2));
    /* cleanup */
    OPENSSL_cleanse(classical_shared, classical_len); free(classical_shared);
    OPENSSL_cleanse(pqc_shared, ss_len); free(pqc_shared);
    return ok;
}

static void *client_thread(void *arg) 
{
    int client_sock = *(int *)arg;
    free(arg);
    printf("[Server][thread] handler start for fd=%d\n", client_sock);

    const char *kem_name = "Kyber512";
    OQS_KEM *kem = NULL;
    uint8_t *server_kem_pk = NULL, *server_kem_sk = NULL, *ciphertext = NULL;
    size_t pk_len=0, sk_len=0, ct_len=0, ss_len=0;

    /* KEM setup */
    /* Initialize PQC KEM (generate keypair). Fail and close socket on error. */
    if (!kem_setup(kem_name, &kem, &server_kem_pk, &server_kem_sk, &pk_len, &sk_len, &ct_len, &ss_len)) 
    {
        fprintf(stderr, "[Server] KEM setup failed\n");
        close(client_sock);
        return NULL;
    }
    ciphertext = malloc(ct_len);
    /* Allocate buffer for the incoming ciphertext; abort on OOM. */
    if (!ciphertext) 
    {
        fprintf(stderr, "[Server] malloc ciphertext failed\n");
        free(server_kem_pk); 
        OPENSSL_cleanse(server_kem_sk, sk_len); 
        free(server_kem_sk); OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    printf("[Server][thread] OQS KEM keypair generated\n");

    /* ECDH generate + serialize */
    unsigned char *server_ec_pub_der = NULL;
    int server_ec_pub_der_len = 0;
    /* Generate ephemeral ECDH keypair and serialize its public key. */
    EVP_PKEY *server_ec_key = ecdh_generate_and_serialize(&server_ec_pub_der, &server_ec_pub_der_len);
    if (!server_ec_key) 
    {
        fprintf(stderr, "[Server] ECDH keygen/serialize failed\n");
        free(server_kem_pk); 
        OPENSSL_cleanse(server_kem_sk, sk_len); 
        free(server_kem_sk); 
        free(ciphertext); 
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    printf("[Server][thread] ECDH keypair generated\n");

    /* generate a session id and send server KEM pk + server EC pub */
    uint32_t session_id = 0;
    /* Use OpenSSL RNG to generate a non-zero 32-bit session id. */
    do {
        if (RAND_bytes((unsigned char *)&session_id, sizeof(session_id)) != 1) 
        {
            fprintf(stderr, "[Server] RAND_bytes failed\n");
            OPENSSL_free(server_ec_pub_der); EVP_PKEY_free(server_ec_key);
            free(server_kem_pk); OPENSSL_cleanse(server_kem_sk, sk_len); free(server_kem_sk);
            free(ciphertext); OQS_KEM_free(kem); close(client_sock);
            return NULL;
        }
    } while (session_id == 0);

    /* Send our PQC public key and serialized ECDH public key to the client. */
    if (!send_server_kem_and_ec(client_sock, session_id, server_kem_pk, pk_len, server_ec_pub_der, server_ec_pub_der_len)) 
    {
        fprintf(stderr, "[Server] failed to send server data\n");
        OPENSSL_free(server_ec_pub_der); 
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk); 
        OPENSSL_cleanse(server_kem_sk, sk_len); 
        free(server_kem_sk); 
        free(ciphertext); 
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    printf("[Server][thread] sent KEM pk (%zu bytes) and server EC pubkey der (%d bytes)\n", pk_len, server_ec_pub_der_len);

    /* receive ciphertext and client EC pub */
    unsigned char *client_ec_pub_der = NULL;
    uint32_t client_ec_pub_len = 0;
    /* Receive ciphertext and client's EC public key (DER). */
    if (!recv_cipher_and_client_ec(client_sock, ciphertext, ct_len, &client_ec_pub_der, &client_ec_pub_len)) 
    {
        fprintf(stderr, "[Server] failed to receive client data\n");
        OPENSSL_free(server_ec_pub_der); 
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk); 
        OPENSSL_cleanse(server_kem_sk, sk_len); 
        free(server_kem_sk); 
        free(ciphertext); 
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    printf("[Server][thread] received ciphertext (%zu bytes) and client EC pubkey der (%u bytes)\n", ct_len, client_ec_pub_len);

    /* decapsulate and derive hybrid key */
    uint8_t final_key[32];
    /* Decapsulate the PQC ciphertext and derive final hybrid key. */
    if (!decaps_and_derive(server_ec_key, kem, server_kem_sk, ciphertext, client_ec_pub_der, client_ec_pub_len, ss_len, final_key)) 
    {
        fprintf(stderr, "[Server] decaps/derive failed\n");
        free(client_ec_pub_der); 
        OPENSSL_free(server_ec_pub_der); 
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk); 
        OPENSSL_cleanse(server_kem_sk, sk_len); 
        free(server_kem_sk); 
        free(ciphertext); 
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }

    /* Do not print final hybrid key in production; keep key material confidential. */

    /* Key-confirmation: derive a confirmation key kc and perform a transcript-bound
     * HMAC exchange. The transcript is SHA256(server_kem_pk || server_ec_pub_der ||
     * ciphertext || client_ec_pub_der). Server expects HMAC(kc, transcript||"client")
     * and replies with HMAC(kc, transcript||"server").
     */
    uint8_t kc_key[32];
    if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"key-confirm", strlen("key-confirm"), kc_key, sizeof(kc_key))) 
    {
        fprintf(stderr, "[Server] hkdf(key-confirm) failed\n");
        /* cleanup and exit thread */
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }

    /* compute transcript hash (include session id to bind session/SUPI) */
    uint8_t transcript[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    uint32_t net_session = htonl(session_id);
    SHA256_Update(&sha_ctx, &net_session, sizeof(net_session));
    SHA256_Update(&sha_ctx, server_kem_pk, pk_len);
    SHA256_Update(&sha_ctx, server_ec_pub_der, server_ec_pub_der_len);
    SHA256_Update(&sha_ctx, ciphertext, ct_len);
    SHA256_Update(&sha_ctx, client_ec_pub_der, client_ec_pub_len);
    SHA256_Final(transcript, &sha_ctx);

    /* receive client HMAC (over transcript||"client") and verify */
    uint8_t client_hmac[SHA256_DIGEST_LENGTH];
    if (full_recv(client_sock, client_hmac, sizeof(client_hmac)) != (ssize_t)sizeof(client_hmac)) 
    {
        fprintf(stderr, "[Server] failed to receive client HMAC\n");
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }

    unsigned int hlen = 0;
    uint8_t expected_client_hmac[SHA256_DIGEST_LENGTH];
    HMAC_CTX *hctx = HMAC_CTX_new();
    if (!hctx) 
    {
        fprintf(stderr, "[Server] HMAC_CTX_new failed\n");
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    if (HMAC_Init_ex(hctx, kc_key, sizeof(kc_key), EVP_sha256(), NULL) != 1) 
    {
        fprintf(stderr, "[Server] HMAC_Init_ex failed\n");
        HMAC_CTX_free(hctx);
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    HMAC_Update(hctx, transcript, sizeof(transcript));
    HMAC_Update(hctx, (const unsigned char *)"client", strlen("client"));
    if (HMAC_Final(hctx, expected_client_hmac, &hlen) != 1) 
    {
        fprintf(stderr, "[Server] HMAC_Final failed\n");
        HMAC_CTX_free(hctx);
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    HMAC_CTX_free(hctx);

    if (CRYPTO_memcmp(client_hmac, expected_client_hmac, sizeof(client_hmac)) != 0) 
    {
        fprintf(stderr, "[Server] client key-confirmation failed\n");
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }

    /* compute and send server HMAC over transcript||"server" */
    uint8_t server_hmac[SHA256_DIGEST_LENGTH];
    HMAC_CTX *hctx2 = HMAC_CTX_new();
    if (!hctx2) 
    {
        fprintf(stderr, "[Server] HMAC_CTX_new failed\n");
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    if (HMAC_Init_ex(hctx2, kc_key, sizeof(kc_key), EVP_sha256(), NULL) != 1) 
    {
        fprintf(stderr, "[Server] HMAC_Init_ex failed\n");
        HMAC_CTX_free(hctx2);
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    HMAC_Update(hctx2, transcript, sizeof(transcript));
    HMAC_Update(hctx2, (const unsigned char *)"server", strlen("server"));
    if (HMAC_Final(hctx2, server_hmac, &hlen) != 1) 
    {
        fprintf(stderr, "[Server] HMAC_Final failed\n");
        HMAC_CTX_free(hctx2);
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    HMAC_CTX_free(hctx2);
    if (full_send(client_sock, server_hmac, sizeof(server_hmac)) != (ssize_t)sizeof(server_hmac)) 
    {
        fprintf(stderr, "[Server] failed to send server HMAC\n");
        OPENSSL_cleanse(kc_key, sizeof(kc_key));
        free(client_ec_pub_der);
        OPENSSL_free(server_ec_pub_der);
        EVP_PKEY_free(server_ec_key);
        free(server_kem_pk);
        OPENSSL_cleanse(server_kem_sk, sk_len);
        free(server_kem_sk);
        free(ciphertext);
        OQS_KEM_free(kem);
        close(client_sock);
        return NULL;
    }
    /* We can now proceed to derive AES keys and accept encrypted messages. */
    OPENSSL_cleanse(kc_key, sizeof(kc_key));

    /* Derive AES-256-GCM key and IV from the hybrid final_key using HKDF.
     * key_info = "enc-key", iv_info = "enc-iv". IV length = 12 bytes.
     */
    uint8_t aead_key[32];
    uint8_t aead_iv[12];
    if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"enc-key", strlen("enc-key"), aead_key, sizeof(aead_key))) 
    {
        fprintf(stderr, "[Server] hkdf(enc-key) failed\n");
    } 
    else if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"enc-iv", strlen("enc-iv"), aead_iv, sizeof(aead_iv))) 
    {
        fprintf(stderr, "[Server] hkdf(enc-iv) failed\n");
        OPENSSL_cleanse(aead_key, sizeof(aead_key));
    } 
    else 
    {
        /* Receive a length-prefixed ciphertext from client: uint32_be(len) || ciphertext || 16-byte tag */
        uint32_t net_len = 0;
        if (full_recv(client_sock, &net_len, sizeof(net_len)) == (ssize_t)sizeof(net_len)) 
        {
            uint32_t ct_len = ntohl(net_len);
            if (ct_len > 0 && ct_len < 10*1024*1024) 
            {
                uint8_t *ct = malloc(ct_len);
                uint8_t tag[16];
                if (ct && full_recv(client_sock, ct, ct_len) == (ssize_t)ct_len && full_recv(client_sock, tag, sizeof(tag)) == (ssize_t)sizeof(tag)) 
                {
                    uint8_t *pt = malloc(ct_len + 16);
                    if (pt) 
                    {
                        int plen = aes256gcm_decrypt(aead_key, aead_iv, sizeof(aead_iv), ct, ct_len, tag, pt);
                        if (plen >= 0) 
                        {
                            printf("[Server] decrypted message (%d bytes): %.*s\n", plen, plen, (char*)pt);
                        } 
                        else 
                        {
                            fprintf(stderr, "[Server] decryption failed/auth failed\n");
                        }
                        OPENSSL_cleanse(pt, ct_len + 16);
                        free(pt);
                    }
                }
                if (ct) free(ct);
            }
        }
        OPENSSL_cleanse(aead_key, sizeof(aead_key));
        OPENSSL_cleanse(aead_iv, sizeof(aead_iv));
    }

    /* final cleanup */
    free(client_ec_pub_der);
    OPENSSL_free(server_ec_pub_der);
    EVP_PKEY_free(server_ec_key);
    free(server_kem_pk); 
    OPENSSL_cleanse(server_kem_sk, sk_len); 
    free(server_kem_sk);
    free(ciphertext); 
    OQS_KEM_free(kem);
    close(client_sock);
    printf("[Server][thread] handler exit for fd=%d\n", client_sock);
    return NULL;
}

int main() 
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    /* Create server socket; fail fast if unavailable. */
    if (server_fd < 0) 
    {
        perror("socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    /* Bind the server socket to the configured address and port. */
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) 
    {
        perror("bind");
        close(server_fd);
        return 1;
    }

    /* Start listening for incoming connections. */
    if (listen(server_fd, 16) < 0) 
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[Server] listening on 0.0.0.0:%d\n", SERVER_PORT);

    /* Main accept loop: accept and dispatch client connections to threads. */
    while (1) 
    {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int client = accept(server_fd, (struct sockaddr *)&peer, &peerlen);
        /* If accept fails due to an interrupt, retry; otherwise log and exit loop. */
        if (client < 0) 
        {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        char peerstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, peerstr, sizeof(peerstr));
        printf("[Server] accepted connection from %s:%d (fd=%d)\n", peerstr, ntohs(peer.sin_port), client);

        /* Allocate memory to pass client fd to the thread; skip if OOM. */
        int *pclient = malloc(sizeof(int));
        if (!pclient) 
        { 
            close(client); 
            continue; 
        }
        *pclient = client;
        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, pclient) != 0) 
        {
            perror("pthread_create");
            free(pclient);
            close(client);
            continue;
        }
        pthread_detach(tid);
    }

    close(server_fd);
    return 0;
}
