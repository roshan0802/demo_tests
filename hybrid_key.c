#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

/* liboqs */
#include <oqs/oqs.h>

#define MAX_SECRET_LEN 64
#define HYBRID_KEY_LEN 32

/* ------------------------------------------------------------------ */
/* Shared hybrid context                                               */
/* ------------------------------------------------------------------ */
typedef struct {
    uint8_t classical_secret[MAX_SECRET_LEN];
    size_t  classical_secret_len;
    int     classical_done;

    uint8_t pqc_secret[MAX_SECRET_LEN];
    size_t  pqc_secret_len;
    int     pqc_done;
} hybrid_ctx_t;

/* ------------------------------------------------------------------ */
/* Classical ECDH thread                                               */
/* ------------------------------------------------------------------ */
void *classical_key_thread(void *arg)
{
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)arg;
    EVP_PKEY_CTX *pctx = NULL, *kctx = NULL, *dctx = NULL;
    EVP_PKEY *params = NULL, *key_a = NULL, *key_b = NULL;
    uint8_t *secret = NULL;
    size_t secret_len = 0;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) goto err;

    if (EVP_PKEY_paramgen_init(pctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
            pctx, NID_X9_62_prime256v1) <= 0) goto err;
    if (EVP_PKEY_paramgen(pctx, &params) <= 0) goto err;

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) goto err;

    if (EVP_PKEY_keygen_init(kctx) <= 0) goto err;
    if (EVP_PKEY_keygen(kctx, &key_a) <= 0) goto err;
    if (EVP_PKEY_keygen(kctx, &key_b) <= 0) goto err;

    dctx = EVP_PKEY_CTX_new(key_a, NULL);
    if (!dctx) goto err;

    if (EVP_PKEY_derive_init(dctx) <= 0) goto err;
    if (EVP_PKEY_derive_set_peer(dctx, key_b) <= 0) goto err;
    if (EVP_PKEY_derive(dctx, NULL, &secret_len) <= 0) goto err;

    secret = OPENSSL_malloc(secret_len);
    if (!secret) goto err;

    if (EVP_PKEY_derive(dctx, secret, &secret_len) <= 0) goto err;

    memcpy(ctx->classical_secret, secret, secret_len);
    ctx->classical_secret_len = secret_len;
    ctx->classical_done = 1;

err:
    if (secret) OPENSSL_free(secret);
    EVP_PKEY_free(key_a);
    EVP_PKEY_free(key_b);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_CTX_free(pctx);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* PQC KEM thread                                                      */
/* ------------------------------------------------------------------ */
void *pqc_key_thread(void *arg)
{
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)arg;
    OQS_KEM *kem = OQS_KEM_new("ML-KEM-512");
    if (!kem) return NULL;

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    if (!pk || !sk || !ct || !ss) goto err;

    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) goto err;
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) goto err;
    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) goto err;

    memcpy(ctx->pqc_secret, ss, kem->length_shared_secret);
    ctx->pqc_secret_len = kem->length_shared_secret;
    ctx->pqc_done = 1;

err:
    if (pk) free(pk);
    if (sk) free(sk);
    if (ct) free(ct);
    if (ss) free(ss);
    OQS_KEM_free(kem);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* HKDF-based hybrid key derivation                                    */
/* ------------------------------------------------------------------ */
int derive_hybrid_key_hkdf(const hybrid_ctx_t *ctx,
                           uint8_t hybrid_key[HYBRID_KEY_LEN])
{
    EVP_PKEY_CTX *pctx = NULL;
    uint8_t ikm[128];
    size_t ikm_len = ctx->classical_secret_len + ctx->pqc_secret_len;

    memcpy(ikm, ctx->classical_secret, ctx->classical_secret_len);
    memcpy(ikm + ctx->classical_secret_len,
           ctx->pqc_secret, ctx->pqc_secret_len);

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return 0;

    if (EVP_PKEY_derive_init(pctx) <= 0) return 0;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) return 0;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len) <= 0) return 0;

    const char *info = "5G-HYBRID-N2-N3";
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen(info)) <= 0)
        return 0;

    size_t out_len = HYBRID_KEY_LEN;
    if (EVP_PKEY_derive(pctx, hybrid_key, &out_len) <= 0)
        return 0;

    EVP_PKEY_CTX_free(pctx);
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return 1;
}

/* ------------------------------------------------------------------ */
/* Main                                                               */
/* ------------------------------------------------------------------ */
int main(void)
{
    pthread_t t1, t2;
    hybrid_ctx_t ctx;
    uint8_t hybrid_key[HYBRID_KEY_LEN];

    memset(&ctx, 0, sizeof(ctx));

    if (pthread_create(&t1, NULL, classical_key_thread, &ctx) != 0)
        return 1;
    if (pthread_create(&t2, NULL, pqc_key_thread, &ctx) != 0)
        return 1;

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    if (!ctx.classical_done || !ctx.pqc_done) {
        printf("Hybrid key exchange failed\n");
        return 1;
    }

    if (!derive_hybrid_key_hkdf(&ctx, hybrid_key)) {
        printf("HKDF derivation failed\n");
        return 1;
    }

    /* Securely wipe intermediate secrets */
    OPENSSL_cleanse(ctx.classical_secret, sizeof(ctx.classical_secret));
    OPENSSL_cleanse(ctx.pqc_secret, sizeof(ctx.pqc_secret));

    printf("Hybrid session key derived successfully\n");
    return 0;
}
