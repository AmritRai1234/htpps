/*
 * main.c — HTPPS Server Entry Point
 * ============================================================================
 * This is where EVERYTHING comes together:
 *
 *   TCP → TLS Handshake → Encrypted HTTP → Response → Encrypted Response → TCP
 *
 * The server loop:
 *   1. Listen on a port (TCP)
 *   2. Accept a client connection (TCP)
 *   3. Perform TLS handshake (TLS)
 *   4. Read encrypted HTTP request (TLS) → decrypt → parse (HTTP)
 *   5. Route request to a handler (Router)
 *   6. Build HTTP response (HTTP)
 *   7. Encrypt and send response (TLS)
 *   8. Close connection
 *   9. Go back to step 2
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "tcp.h"
#include "http.h"
#include "router.h"
#include "tls/tls.h"
#include "crypto/fast/fast_crypto.h"
#include "fast/fast_io.h"

/* Buffer sizes */
#define RECV_BUF_SIZE   (64 * 1024)
#define SEND_BUF_SIZE   (1024 * 1024)
#define FILE_BUF_SIZE   (512 * 1024)

/* Defaults */
#define DEFAULT_HTTP_PORT   8080
#define DEFAULT_HTTPS_PORT  4443
#define DEFAULT_WWW         "./www"
#define DEFAULT_CERT        "./certs/cert.pem"
#define DEFAULT_KEY         "./certs/key.pem"

/*
 * Pre-allocated buffers — allocated ONCE, reused for every request.
 * Eliminates 1.6MB of malloc/free per request (the #1 bottleneck).
 */
static char g_recv_buf[RECV_BUF_SIZE];
static char g_send_buf[SEND_BUF_SIZE];
static char g_file_buf[FILE_BUF_SIZE];

/*
 * RESPONSE CACHE — pre-built HTTP response for index.html.
 * Built once at startup. For "/" requests we skip the entire
 * router → fopen → fread → fclose → http_build pipeline
 * and just send these cached bytes directly.
 *
 * Extra RAM: ~4KB (the file is 3,352 bytes + ~150 bytes of headers).
 * That's less than a single stack frame.
 */
static char  g_cached_index[8192];   /* pre-built full response */
static size_t g_cached_index_len;     /* length of cached response */

static void cache_index_response(const char *www_root)
{
    char filepath[2048];
    snprintf(filepath, sizeof(filepath), "%s/index.html", www_root);

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        g_cached_index_len = 0;
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || (size_t)fsize > sizeof(g_cached_index) - 512) {
        fclose(fp);
        g_cached_index_len = 0;
        return;
    }

    /* Build headers */
    int hdr_len = snprintf(g_cached_index, sizeof(g_cached_index),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n", fsize);

    /* Read body directly after headers */
    size_t body_read = fread(g_cached_index + hdr_len, 1, (size_t)fsize, fp);
    fclose(fp);

    g_cached_index_len = (size_t)hdr_len + body_read;
    printf("[CACHE] index.html: %zu bytes (hdr=%d body=%zu) — will serve from RAM\n",
           g_cached_index_len, hdr_len, body_read);
}

/*
 * handle_http_client — Plain HTTP with JIT'd syscalls + response cache
 *
 * For "/" requests: recv → parse → send cached response → close
 * Skips: router, fopen, fread, fclose, http_build_response
 * Eliminates 4 kernel syscalls and all string formatting per request.
 */
static void handle_http_client(int client_fd, const char *www_root)
{
    size_t response_len = 0;
    int64_t bytes_received = 0;

    /* Direct syscall: read */
    bytes_received = fast_recv(client_fd, g_recv_buf, RECV_BUF_SIZE - 1);
    if (bytes_received <= 0) goto cleanup;
    g_recv_buf[bytes_received] = '\0';

    http_request_t req;
    if (http_parse_request(g_recv_buf, (size_t)bytes_received, &req) < 0) goto cleanup;

    /*
     * FAST PATH: if requesting "/" and we have it cached,
     * skip the entire router/file/response pipeline.
     * Just send the pre-built bytes. Zero disk I/O. Zero formatting.
     */
    if (g_cached_index_len > 0 && strcmp(req.path, "/") == 0) {
        fast_send(client_fd, g_cached_index, g_cached_index_len);
        /* Wipe only recv (cached response is read-only, never changes) */
        if (bytes_received > 0)
            memset(g_recv_buf, 0, (size_t)bytes_received + 1);
        fast_close(client_fd);
        return;
    }

    /* NORMAL PATH: everything else goes through the router */
    http_response_t res;
    memset(&res, 0, sizeof(res));
    router_handle_request(www_root, &req, &res, g_file_buf, FILE_BUF_SIZE);

    if (http_build_response(&res, g_send_buf, SEND_BUF_SIZE, &response_len) < 0) goto cleanup;

    fast_send(client_fd, g_send_buf, response_len);

cleanup:
    /*
     * SECURITY: Wipe ONLY the bytes we actually used.
     */
    if (bytes_received > 0)
        memset(g_recv_buf, 0, (size_t)bytes_received + 1);
    if (response_len > 0)
        memset(g_send_buf, 0, response_len);
    if (res.body_len > 0)
        memset(g_file_buf, 0, (size_t)res.body_len);

    fast_close(client_fd);
}

/*
 * handle_https_client — Full HTTPS with TLS
 */
static void handle_https_client(int client_fd, const char *client_ip,
                                const char *www_root,
                                const char *cert_path, const char *key_path)
{
    char *recv_buf = malloc(RECV_BUF_SIZE);
    char *send_buf = malloc(SEND_BUF_SIZE);
    char *file_buf = malloc(FILE_BUF_SIZE);
    if (!recv_buf || !send_buf || !file_buf) goto cleanup;

    /* Initialize TLS session */
    tls_session sess;
    if (tls_session_init(&sess, client_fd, cert_path, key_path) < 0) {
        fprintf(stderr, "[%s] TLS session init failed\n", client_ip);
        goto cleanup;
    }

    /* Perform TLS handshake */
    if (tls_handshake(&sess) < 0) {
        fprintf(stderr, "[%s] TLS handshake failed\n", client_ip);
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    /* Read decrypted HTTP request through TLS */
    int bytes_received = tls_read(&sess, (uint8_t *)recv_buf, RECV_BUF_SIZE - 1);
    if (bytes_received <= 0) {
        fprintf(stderr, "[%s] Failed to read HTTP request through TLS\n", client_ip);
        tls_session_cleanup(&sess);
        goto cleanup;
    }
    recv_buf[bytes_received] = '\0';

    /* Parse HTTP request */
    http_request_t req;
    if (http_parse_request(recv_buf, (size_t)bytes_received, &req) < 0) {
        printf("[%s] Malformed HTTP request\n", client_ip);
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    printf("[%s] %s %s %s (HTTPS)\n", client_ip, req.method, req.path, req.version);

    /* Route and build response */
    http_response_t res;
    router_handle_request(www_root, &req, &res, file_buf, FILE_BUF_SIZE);

    size_t response_len;
    if (http_build_response(&res, send_buf, SEND_BUF_SIZE, &response_len) < 0) {
        tls_session_cleanup(&sess);
        goto cleanup;
    }

    /* Send encrypted HTTP response through TLS */
    if (tls_write(&sess, (const uint8_t *)send_buf, response_len) < 0) {
        fprintf(stderr, "[%s] Failed to send response through TLS\n", client_ip);
    } else {
        printf("[%s] → %d %s (%zu bytes, encrypted)\n",
               client_ip, res.status, res.status_text, response_len);
    }

    tls_session_cleanup(&sess);

cleanup:
    free(recv_buf);
    free(send_buf);
    free(file_buf);
    tcp_close(client_fd);
}

int main(int argc, char *argv[])
{
    const char *www_root = DEFAULT_WWW;
    const char *cert_path = DEFAULT_CERT;
    const char *key_path = DEFAULT_KEY;
    uint16_t https_port = DEFAULT_HTTPS_PORT;
    uint16_t http_port = DEFAULT_HTTP_PORT;
    int mode = 2; /* 0=http only, 1=https only, 2=both */

    /* Simple arg parsing */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--http") == 0) {
            mode = 0;
        } else if (strcmp(argv[i], "--https") == 0) {
            mode = 1;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            https_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            http_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--www") == 0 && i + 1 < argc) {
            www_root = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  --http          HTTP only mode\n");
            printf("  --https         HTTPS only mode (default: both)\n");
            printf("  --port N        HTTPS port (default: %d)\n", DEFAULT_HTTPS_PORT);
            printf("  --http-port N   HTTP port (default: %d)\n", DEFAULT_HTTP_PORT);
            printf("  --www DIR       Web root directory (default: %s)\n", DEFAULT_WWW);
            printf("  --cert FILE     Certificate PEM (default: %s)\n", DEFAULT_CERT);
            printf("  --key FILE      Private key PEM (default: %s)\n", DEFAULT_KEY);
            return 0;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    /* Detect and enable hardware crypto acceleration */
    crypto_fast_init();

    /* Cache index.html response in RAM (~4KB) */
    cache_index_response(www_root);

    printf("╔═══════════════════════════════════════════╗\n");
    printf("║          ⚡ HTPPS Server                   ║\n");
    printf("║   HTTPS from scratch — zero dependencies  ║\n");
    printf("╠═══════════════════════════════════════════╣\n");
    if (mode != 0) {
        printf("║   HTTPS: https://localhost:%-5u          ║\n", https_port);
    }
    if (mode != 1) {
        printf("║   HTTP:  http://localhost:%-5u           ║\n", http_port);
    }
    printf("║   Root:  %-33s║\n", www_root);
    printf("╚═══════════════════════════════════════════╝\n\n");

    if (mode == 0) {
        /* HTTP only */
        int server_fd = tcp_listen(http_port);
        if (server_fd < 0) return 1;

        while (1) {
            /*
             * fast_accept: direct syscall, skip inet_ntop IP formatting
             * we removed logging, so we don't need the IP string.
             */
            int client_fd = fast_accept(server_fd, NULL, NULL);
            if (client_fd < 0) continue;
            handle_http_client(client_fd, www_root);
        }
    } else {
        /* HTTPS (with optional HTTP) */
        int https_fd = tcp_listen(https_port);
        if (https_fd < 0) return 1;

        /* For simplicity, just serve HTTPS in the main loop.
         * A real server would fork/thread or use select/epoll for both. */
        printf("[INFO] Serving HTTPS on port %u (use --http for plain HTTP)\n\n", https_port);

        while (1) {
            char client_ip[64] = {0};
            int client_fd = tcp_accept(https_fd, client_ip, sizeof(client_ip));
            if (client_fd < 0) continue;
            handle_https_client(client_fd, client_ip, www_root, cert_path, key_path);
        }
    }

    return 0;
}
