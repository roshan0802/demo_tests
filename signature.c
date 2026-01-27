#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <oqs/oqs.h>

/* Generate PQC key pair */
int generate_keypair(OQS_SIG *sig,
                     uint8_t **public_key, size_t *public_key_len,
                     uint8_t **private_key, size_t *private_key_len)
{
    *public_key_len  = sig->length_public_key;
    *private_key_len = sig->length_secret_key;

    *public_key  = malloc(*public_key_len);
    *private_key = malloc(*private_key_len);

    if (*public_key == NULL || *private_key == NULL) {
        return 0;
    }

    if (OQS_SIG_keypair(sig, *public_key, *private_key) != OQS_SUCCESS) {
        return 0;
    }

    return 1;
}

/* Sign message using private key */
int sign_message(OQS_SIG *sig,
                 const uint8_t *message, size_t message_len,
                 const uint8_t *private_key,
                 uint8_t **signature, size_t *signature_len)
{
    *signature_len = sig->length_signature;
    *signature = malloc(*signature_len);

    if (*signature == NULL) {
        return 0;
    }

    if (OQS_SIG_sign(sig,
                     *signature, signature_len,
                     message, message_len,
                     private_key) != OQS_SUCCESS) {
        return 0;
    }

    return 1;
}

/* Verify signature using public key */
int verify_signature(OQS_SIG *sig,
                     const uint8_t *message, size_t message_len,
                     const uint8_t *signature, size_t signature_len,
                     const uint8_t *public_key)
{
    if (OQS_SIG_verify(sig,
                       message, message_len,
                       signature, signature_len,
                       public_key) != OQS_SUCCESS) {
        return 0;
    }

    return 1;
}

int main(void)
{
    int status = 1;
    const char *alg_name = "ML-DSA-44";
    OQS_SIG *sig = NULL;

    uint8_t *public_key = NULL;
    uint8_t *private_key = NULL;
    uint8_t *signature = NULL;
    size_t public_key_len, private_key_len, signature_len;

    const uint8_t message[] = "Hello PQC 5G";
    size_t message_len = strlen((const char *)message);

    /* Initialize algorithm */
    sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        printf("Algorithm initialization failed\n");
        goto cleanup;
    }

    /* Generate keys */
    if (!generate_keypair(sig,
                          &public_key, &public_key_len,
                          &private_key, &private_key_len)) {
        printf("Key generation failed\n");
        goto cleanup;
    }

    /* Sign message */
    if (!sign_message(sig,
                      message, message_len,
                      private_key,
                      &signature, &signature_len)) {
        printf("Signing failed\n");
        goto cleanup;
    }

    /* Verify message */
    if (!verify_signature(sig,
                          message, message_len,
                          signature, signature_len,
                          public_key)) {
        printf("Verification failed\n");
        goto cleanup;
    }

    printf("Signature verification succeeded\n");
    status = 0;

cleanup:
    free(public_key);
    free(private_key);
    free(signature);
    OQS_SIG_free(sig);

    return status;
}
