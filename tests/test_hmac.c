/*
 * test_hmac.c — Verify HMAC-SHA256 against RFC 4231 test vectors
 */

#include <stdio.h>
#include <string.h>
#include "crypto/hmac.h"

static int check_hmac(const char *label,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len,
                      const char *expected_hex)
{
    uint8_t mac[HMAC_SHA256_SIZE];
    hmac_sha256(key, key_len, msg, msg_len, mac);

    char got_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(got_hex + i * 2, "%02x", mac[i]);
    }
    got_hex[64] = '\0';

    int pass = (strcmp(got_hex, expected_hex) == 0);
    printf("[%s] %s\n", pass ? "PASS" : "FAIL", label);
    if (!pass) {
        printf("  Expected: %s\n", expected_hex);
        printf("  Got:      %s\n", got_hex);
    }
    return pass;
}

int main(void)
{
    int passed = 0, total = 0;
    printf("=== HMAC-SHA256 Test Vectors (RFC 4231) ===\n\n");

    /* Test Case 1: Short key */
    total++;
    {
        uint8_t key[20];
        memset(key, 0x0b, 20);
        const char *data = "Hi There";
        passed += check_hmac("TC1: Short key",
            key, 20, (const uint8_t *)data, 8,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    /* Test Case 2: Key = "Jefe" */
    total++;
    {
        const char *key = "Jefe";
        const char *data = "what do ya want for nothing?";
        passed += check_hmac("TC2: Key='Jefe'",
            (const uint8_t *)key, 4,
            (const uint8_t *)data, 28,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    /* Test Case 3: Key and data of 0xaa and 0xdd */
    total++;
    {
        uint8_t key[20], data[50];
        memset(key, 0xaa, 20);
        memset(data, 0xdd, 50);
        passed += check_hmac("TC3: 0xaa key, 0xdd data",
            key, 20, data, 50,
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    }

    /* Test Case 6: Key longer than block size (131 bytes) */
    total++;
    {
        uint8_t key[131];
        memset(key, 0xaa, 131);
        const char *data = "Test Using Larger Than Block-Size Key - Hash Key First";
        passed += check_hmac("TC6: Long key (131 bytes)",
            key, 131,
            (const uint8_t *)data, 54,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    }

    printf("\n=== Results: %d/%d passed ===\n", passed, total);
    return (passed == total) ? 0 : 1;
}
