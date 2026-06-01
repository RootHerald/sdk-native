/**
 * HTTP transport using libcurl — Full Implementation
 *
 * Build requires: libcurl (pkg-config: libcurl)
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "log.h"

#include <curl/curl.h>

/* ------------------------------------------------------------------ */
/*  Internal: write callback for libcurl                              */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *buf;
    size_t buf_len;   /* total capacity */
    size_t written;   /* bytes written so far */
} ResponseCtx;

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    ResponseCtx *rctx = (ResponseCtx *)userdata;
    size_t bytes = size * nmemb;

    if (rctx->written + bytes >= rctx->buf_len) {
        /* Truncate — leave room for null terminator */
        size_t avail = 0;
        if (rctx->buf_len > rctx->written + 1)
            avail = rctx->buf_len - rctx->written - 1;
        if (avail > 0)
            memcpy(rctx->buf + rctx->written, ptr, avail);
        rctx->written += avail;
        rctx->buf[rctx->written] = '\0';
        return bytes; /* tell curl we consumed it all to avoid WRITE_ERROR */
    }

    memcpy(rctx->buf + rctx->written, ptr, bytes);
    rctx->written += bytes;
    rctx->buf[rctx->written] = '\0';
    return bytes;
}

/* ------------------------------------------------------------------ */
/*  http_post_json                                                     */
/* ------------------------------------------------------------------ */

int http_post_json(const char* url, const char* json_body,
                   char* response_buf, size_t response_buf_len)
{
    if (!url || !json_body || !response_buf || response_buf_len == 0)
        return -1;

    response_buf[0] = '\0';

    CURL *curl = curl_easy_init();
    if (!curl) {
        RH_LOG_WARN("http_post_json: curl_easy_init failed\n");
        return -1;
    }

    ResponseCtx rctx = {
        .buf     = response_buf,
        .buf_len = response_buf_len,
        .written = 0
    };

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    /* Follow redirects */
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    /* Verify TLS by default */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    /* User agent */
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "RootHerald-Linux-SDK/0.1");

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        RH_LOG_WARN("http_post_json: curl_easy_perform failed: %s\n",
                curl_easy_strerror(res));
        return -1;
    }

    return (int)http_code;
}

/* ------------------------------------------------------------------ */
/*  http_get                                                           */
/* ------------------------------------------------------------------ */

int http_get(const char* url, char* response_buf, size_t response_buf_len)
{
    if (!url || !response_buf || response_buf_len == 0)
        return -1;

    response_buf[0] = '\0';

    CURL *curl = curl_easy_init();
    if (!curl) {
        RH_LOG_WARN("http_get: curl_easy_init failed\n");
        return -1;
    }

    ResponseCtx rctx = {
        .buf     = response_buf,
        .buf_len = response_buf_len,
        .written = 0
    };

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rctx);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "RootHerald-Linux-SDK/0.1");

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        RH_LOG_WARN("http_get: curl_easy_perform failed: %s\n",
                curl_easy_strerror(res));
        return -1;
    }

    return (int)http_code;
}
