/*
 * test_aes.c — Verify AES-128 against NIST test vectors
 */

#include <stdio.h>
#include <string.h>
#include "crypto/aes.h"

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

/* Parse hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%2x", &b);
        out[i] = (uint8_t)b;
    }
}

int main(void)
{
    int passed = 0, total = 0;
    printf("=== AES-128 Test Vectors ===\n\n");

    /*
     * NIST AES-128 ECB test vector (FIPS 197 Appendix B):
     * Key:       2b7e151628aed2a6abf7158809cf4f3c
     * Plaintext: 3243f6a8885a308d313198a2e0370734
     * Ciphertext: 3925841d02dc09fbdc118597196a0b32
     */
    total++;
    {
        uint8_t key[16], pt[16], ct[16], result[16];
        hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        hex_to_bytes("3243f6a8885a308d313198a2e0370734", pt, 16);
        hex_to_bytes("3925841d02dc09fbdc118597196a0b32", ct, 16);

        aes128_encrypt_block(pt, result, key);
        int pass = (memcmp(result, ct, 16) == 0);
        printf("[%s] NIST ECB encrypt\n", pass ? "PASS" : "FAIL");
        if (!pass) {
            printf("  Expected: "); print_hex(ct, 16); printf("\n");
            printf("  Got:      "); print_hex(result, 16); printf("\n");
        }
        passed += pass;
    }

    /* Test 2: ECB decrypt */
    total++;
    {
        uint8_t key[16], pt[16], ct[16], result[16];
        hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        hex_to_bytes("3243f6a8885a308d313198a2e0370734", pt, 16);
        hex_to_bytes("3925841d02dc09fbdc118597196a0b32", ct, 16);

        aes128_decrypt_block(ct, result, key);
        int pass = (memcmp(result, pt, 16) == 0);
        printf("[%s] NIST ECB decrypt\n", pass ? "PASS" : "FAIL");
        if (!pass) {
            printf("  Expected: "); print_hex(pt, 16); printf("\n");
            printf("  Got:      "); print_hex(result, 16); printf("\n");
        }
        passed += pass;
    }

    /*
     * Test 3: CBC encrypt/decrypt roundtrip
     * Key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  000102030405060708090a0b0c0d0e0f
     */
    total++;
    {
        uint8_t key[16], iv[16];
        hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv, 16);

        const char *msg = "Hello from AES-128-CBC! This is a test message.";
        size_t msg_len = strlen(msg);

        uint8_t ct[128], pt[128];
        size_t ct_len, pt_len;

        aes128_cbc_encrypt((const uint8_t *)msg, msg_len, ct, &ct_len, key, iv);
        int ret = aes128_cbc_decrypt(ct, ct_len, pt, &pt_len, key, iv);

        int pass = (ret == 0 && pt_len == msg_len && memcmp(pt, msg, msg_len) == 0);
        printf("[%s] CBC encrypt/decrypt roundtrip\n", pass ? "PASS" : "FAIL");
        if (!pass) {
            printf("  ret=%d, pt_len=%zu, msg_len=%zu\n", ret, pt_len, msg_len);
        }
        passed += pass;
    }

    /* Test 4: NIST CBC test vector */
    total++;
    {
        uint8_t key[16], iv[16], pt[64], expected_ct[64], ct[80];
        size_t ct_len;

        hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
        hex_to_bytes("000102030405060708090a0b0c0d0e0f", iv, 16);
        hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", pt, 16);

        /* NIST expected CT for this single block (no padding in NIST test) */
        hex_to_bytes("7649abac8119b246cee98e9b12e9197d", expected_ct, 16);

        /* Our CBC adds PKCS#7 padding, so we encrypt 16 bytes → get 32 bytes */
        aes128_cbc_encrypt(pt, 16, ct, &ct_len, key, iv);

        /* First 16 bytes of our output should match the NIST vector */
        int pass = (memcmp(ct, expected_ct, 16) == 0);
        printf("[%s] NIST CBC encrypt (first block)\n", pass ? "PASS" : "FAIL");
        if (!pass) {
            printf("  Expected: "); print_hex(expected_ct, 16); printf("\n");
            printf("  Got:      "); print_hex(ct, 16); printf("\n");
        }
        passed += pass;
    }

    /* Test 5: Empty plaintext (edge case — should be all padding) */
    total++;
    {
        uint8_t key[16] = {0}, iv[16] = {0};
        uint8_t ct[32], pt[32];
        size_t ct_len, pt_len;

        aes128_cbc_encrypt((const uint8_t *)"", 0, ct, &ct_len, key, iv);
        int ret = aes128_cbc_decrypt(ct, ct_len, pt, &pt_len, key, iv);

        int pass = (ret == 0 && pt_len == 0);
        printf("[%s] CBC empty plaintext\n", pass ? "PASS" : "FAIL");
        passed += pass;
    }

    printf("\n=== Results: %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
