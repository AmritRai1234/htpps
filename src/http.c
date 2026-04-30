/*
 * http.c — HTTP/1.1 Parser & Response Builder
 * ============================================================================
 * Parses raw text from TCP into structured request data, and builds
 * response text from structured response data.
 *
 * The core insight: HTTP is just string parsing. That's all a web server does
 * at the HTTP layer — read text, parse it, build text, send it back.
 * ============================================================================
 */

#include "http.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>  /* strcasecmp — case-insensitive string compare */

/*
 * Helper: find the next occurrence of a substring in a bounded buffer.
 * Like strstr() but respects a length limit (won't read past the buffer).
 */
static const char *find_in_buf(const char *buf, size_t buf_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len > buf_len) return NULL;

    for (size_t i = 0; i <= buf_len - needle_len; i++) {
        if (memcmp(buf + i, needle, needle_len) == 0) {
            return buf + i;
        }
    }
    return NULL;
}

int http_parse_request(const char *raw, size_t raw_len, http_request_t *req)
{
    memset(req, 0, sizeof(*req));

    /*
     * STEP 1: Find the end of the request line.
     *
     * The first line is: "GET /path HTTP/1.1\r\n"
     * We need to find the first \r\n to know where it ends.
     */
    const char *line_end = find_in_buf(raw, raw_len, "\r\n");
    if (!line_end) return -1;

    size_t line_len = (size_t)(line_end - raw);
    if (line_len >= 2048) return -1;  /* sanity check */

    /* Copy the request line so we can tokenize it safely */
    char line[2048];
    memcpy(line, raw, line_len);
    line[line_len] = '\0';

    /*
     * STEP 2: Parse the request line.
     *
     * Format: METHOD SP PATH SP VERSION
     * Example: "GET /index.html HTTP/1.1"
     *
     * sscanf with %s reads whitespace-delimited tokens — perfect here.
     */
    if (sscanf(line, "%7s %1023s %15s", req->method, req->path, req->version) != 3) {
        return -1;
    }

    /*
     * STEP 3: Parse headers.
     *
     * Each header is: "Key: Value\r\n"
     * Headers end with an empty line: "\r\n" (just CRLF by itself).
     *
     * We advance past the request line and parse one header per iteration.
     */
    const char *pos = line_end + 2;  /* skip past the first \r\n */
    size_t remaining = raw_len - (size_t)(pos - raw);

    while (remaining >= 2 && req->header_count < HTTP_MAX_HEADERS) {
        /* Check for empty line (end of headers) */
        if (pos[0] == '\r' && pos[1] == '\n') {
            pos += 2;
            break;
        }

        /* Find end of this header line */
        const char *hdr_end = find_in_buf(pos, remaining, "\r\n");
        if (!hdr_end) break;

        size_t hdr_len = (size_t)(hdr_end - pos);

        /* Find the colon separator — "Key: Value" */
        const char *colon = memchr(pos, ':', hdr_len);
        if (colon) {
            size_t key_len = (size_t)(colon - pos);
            const char *val_start = colon + 1;

            /* Skip whitespace after colon */
            while (val_start < hdr_end && *val_start == ' ') val_start++;

            size_t val_len = (size_t)(hdr_end - val_start);

            /* Copy key and value into the header slot */
            if (key_len < HTTP_MAX_HEADER_KEY && val_len < HTTP_MAX_HEADER_VAL) {
                memcpy(req->headers[req->header_count].key, pos, key_len);
                req->headers[req->header_count].key[key_len] = '\0';
                memcpy(req->headers[req->header_count].val, val_start, val_len);
                req->headers[req->header_count].val[val_len] = '\0';
                req->header_count++;
            }
        }

        pos = hdr_end + 2;
        remaining = raw_len - (size_t)(pos - raw);
    }

    /*
     * STEP 4: Body (if any).
     *
     * Everything after the empty line (\r\n\r\n) is the body.
     * For GET requests this is usually empty, but POST requests have data here.
     */
    remaining = raw_len - (size_t)(pos - raw);
    if (remaining > 0) {
        req->body = pos;
        req->body_len = (int)remaining;
    }

    return 0;
}

int http_build_response(const http_response_t *res, char *out_buf, size_t out_buf_size, size_t *out_len)
{
    /*
     * Build the response as text:
     *
     *   HTTP/1.1 200 OK\r\n
     *   Content-Type: text/html\r\n
     *   Content-Length: 45\r\n
     *   \r\n
     *   <html>...</html>
     *
     * We use snprintf to build the header section, then memcpy the body.
     */
    int written = snprintf(out_buf, out_buf_size,
        "HTTP/1.1 %d %s\r\n", res->status, res->status_text);

    if (written < 0 || (size_t)written >= out_buf_size) return -1;

    size_t offset = (size_t)written;

    /* Write each header */
    for (int i = 0; i < res->header_count; i++) {
        written = snprintf(out_buf + offset, out_buf_size - offset,
            "%s: %s\r\n", res->headers[i].key, res->headers[i].val);
        if (written < 0 || offset + (size_t)written >= out_buf_size) return -1;
        offset += (size_t)written;
    }

    /* Empty line to end headers */
    if (offset + 2 >= out_buf_size) return -1;
    out_buf[offset++] = '\r';
    out_buf[offset++] = '\n';

    /* Body */
    if (res->body && res->body_len > 0) {
        if (offset + (size_t)res->body_len > out_buf_size) return -1;
        memcpy(out_buf + offset, res->body, (size_t)res->body_len);
        offset += (size_t)res->body_len;
    }

    *out_len = offset;
    return 0;
}

void http_add_header(http_response_t *res, const char *key, const char *val)
{
    if (res->header_count >= HTTP_MAX_HEADERS) return;

    strncpy(res->headers[res->header_count].key, key, HTTP_MAX_HEADER_KEY - 1);
    res->headers[res->header_count].key[HTTP_MAX_HEADER_KEY - 1] = '\0';
    strncpy(res->headers[res->header_count].val, val, HTTP_MAX_HEADER_VAL - 1);
    res->headers[res->header_count].val[HTTP_MAX_HEADER_VAL - 1] = '\0';
    res->header_count++;
}

const char *http_get_header(const http_request_t *req, const char *key)
{
    /*
     * HTTP headers are case-insensitive per the spec (RFC 7230).
     * "Content-Type" and "content-type" are the same header.
     * strcasecmp does a case-insensitive comparison.
     */
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].key, key) == 0) {
            return req->headers[i].val;
        }
    }
    return NULL;
}
