/*
 * test_sha256.c — Verify our SHA-256 against known test vectors
 * ============================================================================
 * These test vectors are from the NIST standard. If our implementation
 * produces these exact hashes, it's correct.
 * ============================================================================
 */

#include <stdio.h>
#include <string.h>
#include "crypto/sha256.h"

/* Helper: print a hash as hex */
static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

/* Helper: compare hash against expected hex string */
static int check_hash(const char *label, const uint8_t *input, size_t input_len,
                      const char *expected_hex)
{
    uint8_t hash[SHA256_DIGEST_SIZE];
    sha256(input, input_len, hash);

    /* Convert our hash to hex string for comparison */
    char got_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(got_hex + i * 2, "%02x", hash[i]);
    }
    got_hex[64] = '\0';

    int pass = (strcmp(got_hex, expected_hex) == 0);

    printf("[%s] %s\n", pass ? "PASS" : "FAIL", label);
    if (!pass) {
        printf("  Expected: %s\n", expected_hex);
        printf("  Got:      %s\n", got_hex);
    } else {
        printf("  Hash: ");
        print_hex(hash, SHA256_DIGEST_SIZE);
        printf("\n");
    }

    return pass;
}

int main(void)
{
    int passed = 0, total = 0;

    printf("=== SHA-256 Test Vectors ===\n\n");

    /*
     * Test 1: Empty string
     * sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
     */
    total++;
    passed += check_hash("Empty string",
        (const uint8_t *)"", 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    /*
     * Test 2: "abc"
     * This is the most famous SHA-256 test vector, directly from FIPS 180-4.
     */
    total++;
    passed += check_hash("\"abc\"",
        (const uint8_t *)"abc", 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    /*
     * Test 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
     * A longer message that spans two blocks (tests the multi-block path).
     */
    total++;
    const char *msg3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    passed += check_hash("Two-block message",
        (const uint8_t *)msg3, strlen(msg3),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    /*
     * Test 4: Incremental hashing (update called multiple times)
     * Should produce the same result as hashing all at once.
     */
    total++;
    {
        sha256_ctx ctx;
        uint8_t hash[SHA256_DIGEST_SIZE];

        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t *)"abc", 3);
        sha256_update(&ctx, (const uint8_t *)"dbcdecdefdefg", 13);
        sha256_update(&ctx, (const uint8_t *)"efghfghighijhijkijkljklmklmnlmnomnopnopq", 40);
        sha256_final(&ctx, hash);

        char got_hex[65];
        for (int i = 0; i < 32; i++) {
            sprintf(got_hex + i * 2, "%02x", hash[i]);
        }
        got_hex[64] = '\0';

        int pass = (strcmp(got_hex,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);

        printf("[%s] Incremental hashing (3 updates)\n", pass ? "PASS" : "FAIL");
        if (pass) {
            printf("  Hash: %s\n", got_hex);
        }
        passed += pass;
    }

    /*
     * Test 5: Single character "a"
     */
    total++;
    passed += check_hash("Single 'a'",
        (const uint8_t *)"a", 1,
        "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");

    printf("\n=== Results: %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
