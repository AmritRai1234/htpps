/*
 * test_rsa.c — Test RSA key loading and encrypt/decrypt
 *
 * We use openssl CLI to encrypt a test message with the public key,
 * then verify our RSA implementation can decrypt it.
 *
 * But first, we test just the key loading and basic bignum RSA math.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "crypto/rsa.h"
#include "crypto/bignum.h"
#include "crypto/pem.h"

int main(void)
{
    int passed = 0, total = 0;
    printf("=== RSA Tests ===\n\n");

    /* Test 1: Bignum basics */
    total++;
    {
        bignum a, b, c;
        bn_from_uint(&a, 12345);
        bn_from_uint(&b, 67890);
        bn_add(&c, &a, &b);

        int pass = (c.words[0] == 80235);
        printf("[%s] Bignum add: 12345 + 67890 = %u\n", pass ? "PASS" : "FAIL", c.words[0]);
        passed += pass;
    }

    /* Test 2: Bignum multiply */
    total++;
    {
        bignum a, b, c;
        bn_from_uint(&a, 9999);
        bn_from_uint(&b, 9999);
        bn_mul(&c, &a, &b);

        int pass = (c.words[0] == 99980001);
        printf("[%s] Bignum mul: 9999 * 9999 = %u\n", pass ? "PASS" : "FAIL", c.words[0]);
        passed += pass;
    }

    /* Test 3: Bignum mod_exp (small numbers) */
    total++;
    {
        bignum base, exp, mod, result;
        bn_from_uint(&base, 4);
        bn_from_uint(&exp, 13);
        bn_from_uint(&mod, 497);
        bn_mod_exp(&result, &base, &exp, &mod);

        /* 4^13 mod 497 = 445 */
        int pass = (result.words[0] == 445);
        printf("[%s] mod_exp: 4^13 mod 497 = %u (expected 445)\n",
               pass ? "PASS" : "FAIL", result.words[0]);
        passed += pass;
    }

    /* Test 4: Load RSA key from PEM */
    total++;
    {
        rsa_key key;
        int ret = rsa_load_private_key("certs/key.pem", &key);

        int pass = (ret == 0 && key.bits >= 2048);
        printf("[%s] Load RSA key: %d bits, e=%u\n",
               pass ? "PASS" : "FAIL", key.bits, key.e.words[0]);
        passed += pass;

        if (ret == 0) {
            /* Test 5: RSA encrypt with public key, decrypt with private key */
            total++;

            /* Create a small test number and encrypt with public key: ct = pt^e mod n */
            bignum pt_bn, ct_bn, decrypted_bn;
            bn_from_uint(&pt_bn, 42);

            printf("[RSA] Encrypting test value 42...\n");
            bn_mod_exp(&ct_bn, &pt_bn, &key.e, &key.n);

            printf("[RSA] Decrypting...\n");
            bn_mod_exp(&decrypted_bn, &ct_bn, &key.d, &key.n);

            pass = (bn_cmp(&pt_bn, &decrypted_bn) == 0);
            printf("[%s] RSA encrypt/decrypt roundtrip: %u → encrypt → decrypt → %u\n",
                   pass ? "PASS" : "FAIL", pt_bn.words[0], decrypted_bn.words[0]);
            passed += pass;
        }
    }

    printf("\n=== Results: %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
