/* Hybrid client: performs matching KEM+ECDH exchange with the server and
 * derives the same final hybrid key via HKDF-SHA256.
 *
 * Protocol (matching server):
 * 1) server -> client: KEM public key (fixed length)
 * 2) server -> client: uint32_be(len of server EC pub DER) + server EC pub DER
 * 3) client: generate client EC keypair
 * 4) client: OQS_KEM_encaps -> ciphertext (fixed length) + pqc_shared
 * 5) client -> server: ciphertext
 * 6) client -> server: uint32_be(len of client EC pub DER) + client EC pub DER
 * 7) both derive classical ECDH secret and then HKDF(classical||pqc)
 *
 * Build: gcc hybrid_client_key.c -o hybrid_client_key -loqs -lssl -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

#define SERVER_PORT 5555
/* Default server address to connect to (loopback). Change if needed. */
#define SERVER_ADDR "127.0.0.1"


static ssize_t full_recv(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        /* If recv returned an error, retry on EINTR (interrupted syscall),
         * otherwise propagate the error.
         */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        /* If recv returned 0 the peer performed an orderly shutdown. Return
         * 0 to indicate EOF to the caller.
         */
        if (r == 0) return 0;
        p += r;
        left -= r;
    }
    return (ssize_t)len;
}

static ssize_t full_send(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t left = len;
    while (left > 0) {
        ssize_t w = send(fd, p, left, 0);
        /* Retry on EINTR, otherwise propagate the error. */
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        /* send returning 0 is unusual for blocking sockets but handle it
         * by treating it as an error (peer closed connection).
         */
        if (w == 0) return 0;
        p += w;
        left -= w;
    }
    return (ssize_t)len;
}

/* HKDF helpers: separate Extract and Expand so we can perform sequential Extract
 * mixing (recommended for hybrid KEM + ECDH). We provide:
 *  - hkdf_extract(prk_out, ikm, ikm_len, salt, salt_len)
 *  - hkdf_expand(prk, prk_len, info, info_len, out, out_len)
 */
static int hkdf_extract(uint8_t *prk_out, const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len) {
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk_out, &prk_len))
        return 0;
    return (prk_len == SHA256_DIGEST_LENGTH) ? 1 : 0;
}

static int hkdf_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len) {
    const size_t hash_len = SHA256_DIGEST_LENGTH;
    uint8_t t[SHA256_DIGEST_LENGTH];
    size_t t_len = 0;
    size_t n = (out_len + hash_len - 1) / hash_len;
    if (n == 0 || n > 255) return 0;

    uint8_t *okm = out;
    size_t remaining = out_len;
    for (uint8_t i = 1; i <= n; ++i) {
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) return 0;
        if (HMAC_Init_ex(hctx, prk, (int)prk_len, EVP_sha256(), NULL) != 1) { HMAC_CTX_free(hctx); return 0; }
        if (t_len > 0) HMAC_Update(hctx, t, t_len);
        if (info && info_len > 0) HMAC_Update(hctx, info, info_len);
        uint8_t c = i;
        HMAC_Update(hctx, &c, 1);
        unsigned int len = 0;
        if (HMAC_Final(hctx, t, &len) != 1) { HMAC_CTX_free(hctx); return 0; }
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

/* AES-256-GCM helpers (same as server) ---------------------------------- */
static int aes256gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                            const uint8_t *plaintext, int plaintext_len,
                            uint8_t *ciphertext_out, uint8_t *tag_out) 
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) 
        return -1;
    int len = 0, clen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) 
        goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) 
        goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) 
        goto err;
    if (plaintext_len > 0) 
    {
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, plaintext_len) != 1) goto err;
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
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto err;
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

/* --- client helper functions to keep main small --- */

static int recv_server_kem_and_ec(int sock, OQS_KEM *kem,
                                  uint32_t *session_id_out,
                                  uint8_t **server_kem_pk_out,
                                  unsigned char **server_ec_pub_der_out,
                                  uint32_t *server_ec_pub_len_out) 
{
    size_t pk_len = kem->length_public_key;
    uint8_t *pk = malloc(pk_len);
    /* Fail if we cannot allocate storage for the KEM public key. */
    if (!pk) return 0;
    /* Receive the fixed-length KEM public key from the server. If recv
     * does not return the expected number of bytes, free and fail.
     */
    /* First read the session id (network order). */
    uint32_t net_sid = 0;
    if (full_recv(sock, &net_sid, sizeof(net_sid)) != (ssize_t)sizeof(net_sid)) 
    { 
        free(pk); 
        return 0; 
    }
    *session_id_out = ntohl(net_sid);
    if (full_recv(sock, pk, pk_len) != (ssize_t)pk_len) 
    { 
        free(pk); 
        return 0; 
    }

    uint32_t net_len = 0;
    /* Read a 32-bit network-order length for the server EC public key DER. */
    if (full_recv(sock, &net_len, sizeof(net_len)) != (ssize_t)sizeof(net_len)) 
    { 
        free(pk); 
        return 0; 
    }
    uint32_t len = ntohl(net_len);
    /* Sanity check the received length to avoid OOM or malicious values. */
    if (len == 0 || len > 10000) 
    { 
        free(pk); 
        return 0; 
    }
    /* Allocate buffer for server EC public key DER and receive it. */
    unsigned char *der = malloc(len);
    if (!der) 
    { 
        free(pk); 
        return 0; 
    }
    if (full_recv(sock, der, len) != (ssize_t)len) 
    { 
        free(der); 
        free(pk); 
        return 0; 
    }

    *server_kem_pk_out = pk;
    *server_ec_pub_der_out = der;
    *server_ec_pub_len_out = len;
    return 1;
}

static EVP_PKEY *ecdh_generate_and_serialize_client(unsigned char **out_der, int *out_len) 
{
    /* Create a new EC key on the P-256 curve. Fail if allocation fails. */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) 
        return NULL;
    /* Generate the ephemeral EC keypair; on failure free and return NULL. */
    if (EC_KEY_generate_key(ec_key) != 1) 
    { 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    /* Wrap EC_KEY into an EVP_PKEY for use with EVP APIs. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) 
    { 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    /* Assign the EC key to the EVP_PKEY; ownership of ec_key transfers to pkey. */
    if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) 
    { 
        EVP_PKEY_free(pkey); 
        EC_KEY_free(ec_key); 
        return NULL; 
    }
    /* Serialize the EVP_PKEY public key to DER format for sending. */
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

static int kem_encapsulate_and_alloc(OQS_KEM *kem, uint8_t *server_kem_pk,
                                     uint8_t **ciphertext_out, uint8_t **pqc_shared_out,
                                     size_t ct_len, size_t ss_len) 
{
    uint8_t *ct = malloc(ct_len);
    uint8_t *ss = malloc(ss_len);
        /* Allocate buffers for ciphertext and shared secret; fail on OOM. */
        if (!ct || !ss) 
        { 
            if (ct) 
                free(ct); 
            if (ss) 
                free(ss); 
            return 0; 
        }
        /* Perform KEM encapsulation using the server's KEM public key. */
        if (OQS_KEM_encaps(kem, ct, ss, server_kem_pk) != OQS_SUCCESS) 
        { 
            free(ct); 
            free(ss); 
            return 0; 
        }
    *ciphertext_out = ct; 
    *pqc_shared_out = ss; 
    return 1;
}

static int send_cipher_and_client_ec(int sock, uint8_t *ciphertext, size_t ct_len,
                                     unsigned char *client_ec_pub_der, int client_ec_pub_der_len) 
{
    /* Send the fixed-length ciphertext to the server; on failure abort. */
    if (full_send(sock, ciphertext, ct_len) != (ssize_t)ct_len) 
        return 0;
    uint32_t net_len = htonl((uint32_t)client_ec_pub_der_len);
    if (full_send(sock, &net_len, sizeof(net_len)) != (ssize_t)sizeof(net_len)) 
        return 0;
    if (full_send(sock, client_ec_pub_der, client_ec_pub_der_len) != client_ec_pub_der_len) 
        return 0;
    return 1;
}

static int derive_classical_and_hkdf(EVP_PKEY *client_ec_key, unsigned char *server_ec_pub_der, uint32_t server_ec_pub_len,
                                    uint8_t *pqc_shared, size_t ss_len, uint8_t *out_final_key /*32 bytes*/) 
{
    const unsigned char *pp = server_ec_pub_der;
    /* Reconstruct server EVP_PKEY from DER; fail if parsing fails. */
    EVP_PKEY *server_pub = d2i_PUBKEY(NULL, &pp, server_ec_pub_len);
    if (!server_pub) 
        return 0;
    /* Create an EVP_PKEY_CTX for deriving the shared secret; ensure it
     * was allocated successfully.
     */
    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(client_ec_key, NULL);
    if (!derive_ctx) 
    { 
        EVP_PKEY_free(server_pub); 
        return 0; 
    }
    /* Initialize the derive operation and set the peer public key. If
     * either call fails, clean up and return error.
     */
    if (EVP_PKEY_derive_init(derive_ctx) <= 0 || EVP_PKEY_derive_set_peer(derive_ctx, server_pub) <= 0) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(server_pub); 
        return 0; 
    }
    size_t classical_len = 0;
    /* Query the buffer length required for the classical shared secret. */
    if (EVP_PKEY_derive(derive_ctx, NULL, &classical_len) <= 0) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(server_pub); 
        return 0; 
    }
    /* Allocate buffer for the classical ECDH shared secret. */
    uint8_t *classical_shared = malloc(classical_len);
    if (!classical_shared) 
    { 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(server_pub); 
        return 0; 
    }
    /* Perform the key derivation into the allocated buffer. */
    if (EVP_PKEY_derive(derive_ctx, classical_shared, &classical_len) <= 0) 
    { 
        OPENSSL_cleanse(classical_shared, classical_len); 
        free(classical_shared); 
        EVP_PKEY_CTX_free(derive_ctx); 
        EVP_PKEY_free(server_pub); 
        return 0; 
    }
    EVP_PKEY_CTX_free(derive_ctx); EVP_PKEY_free(server_pub);

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
        ok = 0; goto client_derive_cleanup;
    }
    if (!hkdf_extract(prk2, pqc_shared, ss_len, prk1, SHA256_DIGEST_LENGTH)) {
        ok = 0; goto client_derive_cleanup;
    }
    if (!hkdf_expand(prk2, SHA256_DIGEST_LENGTH, (const uint8_t *)info, strlen(info), out_final_key, 32)) {
        ok = 0; goto client_derive_cleanup;
    }
    ok = 1;

client_derive_cleanup:
    OPENSSL_cleanse(prk1, sizeof(prk1));
    OPENSSL_cleanse(prk2, sizeof(prk2));
    OPENSSL_cleanse(classical_shared, classical_len); free(classical_shared);
    return ok;
}

int main() 
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    /* Create a TCP socket; if socket() fails report the error and exit. */
    if (sock < 0) 
    { 
        perror("socket"); 
        return 1; 
    }
    printf("[Client] socket created (fd=%d)\n", sock);

    struct sockaddr_in srv;
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &srv.sin_addr);
    /* Connect to the server; on failure clean up and exit. */
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) 
    { 
        perror("connect"); 
        close(sock); 
        return 1; 
    }
    printf("[Client] connected to %s:%d\n", SERVER_ADDR, SERVER_PORT);

    const char *kem_name = "Kyber512";
    OQS_KEM *kem = OQS_KEM_new(kem_name);
    /* Instantiate the OQS KEM object for the chosen algorithm; fail if
     * allocation or algorithm selection fails.
     */
    if (!kem) 
    { 
        fprintf(stderr, "[Client] OQS_KEM_new(%s) failed\n", kem_name); 
        close(sock); 
        return 1; 
    }
    size_t pk_len = kem->length_public_key;
    size_t ct_len = kem->length_ciphertext;
    size_t ss_len = kem->length_shared_secret;

    uint8_t *server_kem_pk = NULL;
    unsigned char *server_ec_pub_der = NULL;
    uint32_t server_ec_pub_len = 0;
    /* Receive server session id, KEM public key and server EC public key DER. */
    uint32_t session_id = 0;
    if (!recv_server_kem_and_ec(sock, kem, &session_id, &server_kem_pk, &server_ec_pub_der, &server_ec_pub_len)) 
    {
        fprintf(stderr, "[Client] failed to receive server data\n");
        OQS_KEM_free(kem); 
        close(sock); 
        return 1;
    }
    printf("[Client] received KEM pk (%zu bytes)\n", pk_len);
    printf("[Client] received server EC pubkey der (%u bytes)\n", server_ec_pub_len);

    /* Generate client ECDH and serialize */
    unsigned char *client_ec_pub_der = NULL;
    int client_ec_pub_der_len = 0;
    EVP_PKEY *client_ec_key = ecdh_generate_and_serialize_client(&client_ec_pub_der, &client_ec_pub_der_len);
    /* If client EC key generation failed, clean up and exit. */
    if (!client_ec_key) 
    { 
        fprintf(stderr, "[Client] ECDH keygen failed\n"); 
        free(server_kem_pk); 
        OPENSSL_free(server_ec_pub_der); 
        OQS_KEM_free(kem); 
        close(sock); 
        return 1; 
    }

    /* KEM encaps */
    uint8_t *ciphertext = NULL;
    uint8_t *pqc_shared = NULL;
    /* Encapsulate using server KEM public key to produce ciphertext and pqc_shared. */
    if (!kem_encapsulate_and_alloc(kem, server_kem_pk, &ciphertext, &pqc_shared, ct_len, ss_len)) 
    {
        fprintf(stderr, "[Client] KEM encaps failed\n");
        EVP_PKEY_free(client_ec_key); 
        OPENSSL_free(client_ec_pub_der); 
        free(server_kem_pk); 
        OPENSSL_free(server_ec_pub_der); 
        OQS_KEM_free(kem); 
        close(sock); 
        return 1;
    }
    printf("[Client] OQS encaps OK (ct_len=%zu ss_len=%zu)\n", ct_len, ss_len);

    /* Send ciphertext and client EC pub */
    /* Send the ciphertext and the serialized client EC public key. */
    if (!send_cipher_and_client_ec(sock, ciphertext, ct_len, client_ec_pub_der, client_ec_pub_der_len)) 
    {
        fprintf(stderr, "[Client] failed to send ciphertext/ec pub\n"); 
        free(ciphertext); 
        free(pqc_shared); 
        OPENSSL_free(client_ec_pub_der); 
        EVP_PKEY_free(client_ec_key); 
        free(server_kem_pk); 
        OPENSSL_free(server_ec_pub_der); 
        OQS_KEM_free(kem); 
        close(sock); 
        return 1;
    }
    printf("[Client] sent ciphertext and client EC pub (%d bytes)\n", client_ec_pub_der_len);

    /* Derive classical and hybrid */
    uint8_t final_key[32];
    /* Derive classical ECDH secret and run HKDF over (classical||pqc). */
    if (!derive_classical_and_hkdf(client_ec_key, server_ec_pub_der, server_ec_pub_len, pqc_shared, ss_len, final_key)) 
    {
        fprintf(stderr, "[Client] derive/hkdf failed\n"); 
        free(ciphertext); 
        free(pqc_shared); 
        OPENSSL_free(client_ec_pub_der); 
        EVP_PKEY_free(client_ec_key); 
        free(server_kem_pk); 
        OPENSSL_free(server_ec_pub_der); 
        OQS_KEM_free(kem); 
        close(sock); 
        return 1;
    }
    /* DO NOT print final hybrid key in production; keep it in memory only. */

    /* Key-confirmation: derive kc and perform transcript-bound HMAC exchange
     * to ensure both sides derived the same final_key. The transcript hash is
     * SHA256(server_kem_pk || server_ec_pub_der || ciphertext || client_ec_pub_der).
     * Client sends HMAC(kc, transcript_hash || "client") and expects
     * HMAC(kc, transcript_hash || "server") in reply.
     */
    uint8_t kc_key[32];
    if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"key-confirm", strlen("key-confirm"), kc_key, sizeof(kc_key))) 
    {
        fprintf(stderr, "[Client] hkdf(key-confirm) failed\n");
    } 
    else 
    {
    /* compute transcript hash (include session id to bind session/SUPI) */
    uint8_t transcript[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    uint32_t net_session = htonl(session_id);
    SHA256_Update(&sha_ctx, &net_session, sizeof(net_session));
    SHA256_Update(&sha_ctx, server_kem_pk, pk_len);
    SHA256_Update(&sha_ctx, server_ec_pub_der, server_ec_pub_len);
    SHA256_Update(&sha_ctx, ciphertext, ct_len);
    SHA256_Update(&sha_ctx, client_ec_pub_der, client_ec_pub_der_len);
    SHA256_Final(transcript, &sha_ctx);

        unsigned int hlen = 0;
        uint8_t client_hmac[SHA256_DIGEST_LENGTH];
        /* HMAC over transcript || "client" */
        HMAC_CTX *hctx = HMAC_CTX_new();
        if (!hctx) 
        {
            fprintf(stderr, "[Client] HMAC_CTX_new failed\n");
            OPENSSL_cleanse(kc_key, sizeof(kc_key));
        } 
        else if (HMAC_Init_ex(hctx, kc_key, sizeof(kc_key), EVP_sha256(), NULL) != 1) 
        {
            fprintf(stderr, "[Client] HMAC_Init_ex failed\n");
            HMAC_CTX_free(hctx); OPENSSL_cleanse(kc_key, sizeof(kc_key));
        } 
        else 
        {
            HMAC_Update(hctx, transcript, sizeof(transcript));
            HMAC_Update(hctx, (const unsigned char *)"client", strlen("client"));
            if (HMAC_Final(hctx, client_hmac, &hlen) != 1) 
            {
                fprintf(stderr, "[Client] HMAC_Final failed\n");
                HMAC_CTX_free(hctx); OPENSSL_cleanse(kc_key, sizeof(kc_key));
            } 
            else 
            {
                HMAC_CTX_free(hctx);
                /* send client HMAC */
                if (full_send(sock, client_hmac, sizeof(client_hmac)) != (ssize_t)sizeof(client_hmac)) 
                {
                    fprintf(stderr, "[Client] failed to send client HMAC\n");
                    OPENSSL_cleanse(kc_key, sizeof(kc_key));
                } 
                else 
                {
                    /* receive server HMAC and verify */
                    uint8_t server_hmac[SHA256_DIGEST_LENGTH];
                    if (full_recv(sock, server_hmac, sizeof(server_hmac)) != (ssize_t)sizeof(server_hmac)) 
                    {
                        fprintf(stderr, "[Client] failed to receive server HMAC\n");
                        OPENSSL_cleanse(kc_key, sizeof(kc_key));
                    } 
                    else 
                    {
                        /* compute expected server HMAC = HMAC(kc, transcript || "server") */
                        uint8_t expected_server_hmac[SHA256_DIGEST_LENGTH];
                        HMAC_CTX *hctx2 = HMAC_CTX_new();
                        if (!hctx2) 
                        {
                            fprintf(stderr, "[Client] HMAC_CTX_new failed\n");
                            OPENSSL_cleanse(kc_key, sizeof(kc_key));
                        } 
                        else if (HMAC_Init_ex(hctx2, kc_key, sizeof(kc_key), EVP_sha256(), NULL) != 1) 
                        {
                            fprintf(stderr, "[Client] HMAC_Init_ex failed\n");
                            HMAC_CTX_free(hctx2); OPENSSL_cleanse(kc_key, sizeof(kc_key));
                        } 
                        else 
                        {
                            HMAC_Update(hctx2, transcript, sizeof(transcript));
                            HMAC_Update(hctx2, (const unsigned char *)"server", strlen("server"));
                            if (HMAC_Final(hctx2, expected_server_hmac, &hlen) != 1) 
                            {
                                fprintf(stderr, "[Client] HMAC_Final failed\n");
                                HMAC_CTX_free(hctx2); OPENSSL_cleanse(kc_key, sizeof(kc_key));
                            } 
                            else 
                            {
                                HMAC_CTX_free(hctx2);
                                if (CRYPTO_memcmp(server_hmac, expected_server_hmac, sizeof(server_hmac)) != 0) 
                                {
                                    fprintf(stderr, "[Client] server key-confirmation failed\n");
                                    OPENSSL_cleanse(kc_key, sizeof(kc_key));
                                } 
                                else 
                                {
                                    /* Key-confirmation succeeded; derive AEAD and send encrypted message. */
                                    uint8_t aead_key[32];
                                    uint8_t aead_iv[12];
                                    if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"enc-key", strlen("enc-key"), aead_key, sizeof(aead_key))) 
                                    {
                                        fprintf(stderr, "[Client] hkdf(enc-key) failed\n");
                                    } 
                                    else if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"enc-iv", strlen("enc-iv"), aead_iv, sizeof(aead_iv))) 
                                    {
                                        fprintf(stderr, "[Client] hkdf(enc-iv) failed\n");
                                        OPENSSL_cleanse(aead_key, sizeof(aead_key));
                                    } 
                                    else 
                                    {
                                        const char msg[] = "Hello from client (encrypted)";
                                        size_t mlen = strlen(msg);
                                        uint8_t *ct = malloc(mlen + 16);
                                        uint8_t tag[16];
                                        if (ct) 
                                        {
                                            int ctlen = aes256gcm_encrypt(aead_key, aead_iv, sizeof(aead_iv), (const uint8_t *)msg, (int)mlen, ct, tag);
                                            if (ctlen >= 0) 
                                            {
                                                uint32_t net_len = htonl((uint32_t)ctlen);
                                                full_send(sock, &net_len, sizeof(net_len));
                                                full_send(sock, ct, ctlen);
                                                full_send(sock, tag, sizeof(tag));
                                            }
                                            OPENSSL_cleanse(ct, mlen + 16);
                                            free(ct);
                                        }
                                        OPENSSL_cleanse(aead_key, sizeof(aead_key));
                                        OPENSSL_cleanse(aead_iv, sizeof(aead_iv));
                                    }
                                    OPENSSL_cleanse(kc_key, sizeof(kc_key));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    /* Derive AEAD key, but use a per-message random IV (12 bytes). */
     uint8_t aead_key[32];
    if (!hkdf_sha256(final_key, sizeof(final_key), (const uint8_t *)"enc-key", strlen("enc-key"), aead_key, sizeof(aead_key))) 
    {
        fprintf(stderr, "[Client] hkdf(enc-key) failed\n");
    } 
    else 
    {
        const char msg[] = "Hello from client (encrypted)";
        size_t mlen = strlen(msg);
        uint8_t *ct = malloc(mlen + 16);
        uint8_t tag[16];
        uint8_t iv[12];
        if (RAND_bytes(iv, sizeof(iv)) != 1) 
        {
            fprintf(stderr, "[Client] RAND_bytes(iv) failed\n");
        } 
        else if (ct) 
        {
            int ctlen = aes256gcm_encrypt(aead_key, iv, sizeof(iv), (const uint8_t *)msg, (int)mlen, ct, tag);
            if (ctlen >= 0) 
            {
                /* send iv || uint32_be(ctlen) || ct || tag */
                full_send(sock, iv, sizeof(iv));
                uint32_t net_len = htonl((uint32_t)ctlen);
                full_send(sock, &net_len, sizeof(net_len));
                full_send(sock, ct, ctlen);
                full_send(sock, tag, sizeof(tag));
            }
            OPENSSL_cleanse(ct, mlen + 16);
            free(ct);
        }
     OPENSSL_cleanse(aead_key, sizeof(aead_key));
    }
    /* cleanup */
    free(ciphertext); 
    OPENSSL_free(client_ec_pub_der); 
    EVP_PKEY_free(client_ec_key); 
    free(server_kem_pk); 
    OPENSSL_free(server_ec_pub_der); 
    free(pqc_shared); 
    OQS_KEM_free(kem); 
    close(sock);
    return 0;
}
