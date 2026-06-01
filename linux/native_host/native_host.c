/**
 *  Root Herald Native Messaging Host — Linux
 *
 * Bridges browser extension requests to the  Root Herald client SDK
 * via Chrome/Edge/Firefox native messaging protocol (length-prefixed JSON
 * on stdin/stdout).
 *
 * JSON parsing and building is done with simple strstr-based helpers
 * (same approach as the Windows json_helpers.h, but in C).
 */

#include "rootherald_linux.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Native messaging I/O                                               */
/* ------------------------------------------------------------------ */

static char* read_message(void)
{
    uint32_t length = 0;
    if (fread(&length, sizeof(length), 1, stdin) != 1)
        return NULL;

    if (length > 1024 * 1024) /* 1 MB limit */
        return NULL;

    char* message = malloc(length + 1);
    if (!message) return NULL;

    if (fread(message, 1, length, stdin) != length) {
        free(message);
        return NULL;
    }
    message[length] = '\0';
    return message;
}

static void write_message(const char* message)
{
    uint32_t length = (uint32_t)strlen(message);
    fwrite(&length, sizeof(length), 1, stdout);
    fwrite(message, 1, length, stdout);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/*  Minimal JSON parser (strstr-based, flat objects only)             */
/* ------------------------------------------------------------------ */

/**
 * Extract a string value from JSON by key.
 * Writes result into dst (up to dst_len-1 chars + null terminator).
 * Returns length of extracted value, or 0 if not found.
 */
static size_t json_get(const char* json, const char* key, char* dst, size_t dst_len)
{
    if (!json || !key || !dst || dst_len == 0) return 0;
    dst[0] = '\0';

    /* Build search: "key" */
    char search[256];
    int slen = snprintf(search, sizeof(search), "\"%s\"", key);
    if (slen < 0 || (size_t)slen >= sizeof(search)) return 0;

    const char* pos = strstr(json, search);
    if (!pos) return 0;

    /* Advance past key and find colon */
    pos += slen;
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;
    if (*pos != ':') return 0;
    pos++;
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') pos++;

    if (*pos == '"') {
        /* String value */
        pos++;
        size_t di = 0;
        while (*pos && *pos != '"') {
            char ch;
            if (*pos == '\\' && *(pos + 1)) {
                pos++;
                if (*pos == 'n') ch = '\n';
                else if (*pos == 't') ch = '\t';
                else if (*pos == '\\') ch = '\\';
                else if (*pos == '"') ch = '"';
                else ch = *pos;
            } else {
                ch = *pos;
            }
            if (di + 1 < dst_len)
                dst[di] = ch;
            di++;
            pos++;
        }
        if (di < dst_len) dst[di] = '\0';
        else dst[dst_len - 1] = '\0';
        return di;
    } else {
        /* Non-string: number, bool, null, nested */
        size_t di = 0;
        int depth = 0;
        while (*pos) {
            if (*pos == '{' || *pos == '[') depth++;
            else if (*pos == '}' || *pos == ']') {
                if (depth == 0) break;
                depth--;
            } else if (depth == 0 && (*pos == ',' || *pos == '}')) {
                break;
            }
            if (di + 1 < dst_len)
                dst[di] = *pos;
            di++;
            pos++;
        }
        if (di < dst_len) dst[di] = '\0';
        else dst[dst_len - 1] = '\0';
        return di;
    }
}

/* ------------------------------------------------------------------ */
/*  Minimal JSON builder                                               */
/* ------------------------------------------------------------------ */

static void json_append_string(char* buf, size_t buf_len, size_t* offset,
                               const char* key, const char* value, int is_first)
{
    size_t off = *offset;
    if (!is_first && off + 1 < buf_len)
        buf[off++] = ',';

    int n = snprintf(buf + off, buf_len - off, "\"%s\":\"", key);
    if (n > 0) off += (size_t)n;

    /* Escape value characters */
    for (const char* p = value; *p && off + 2 < buf_len; p++) {
        if (*p == '"' || *p == '\\') {
            buf[off++] = '\\';
            buf[off++] = *p;
        } else if (*p == '\n') {
            buf[off++] = '\\';
            buf[off++] = 'n';
        } else {
            buf[off++] = *p;
        }
    }
    if (off + 1 < buf_len) buf[off++] = '"';
    buf[off] = '\0';
    *offset = off;
}

static void json_append_raw(char* buf, size_t buf_len, size_t* offset,
                            const char* key, const char* raw_value, int is_first)
{
    size_t off = *offset;
    if (!is_first && off + 1 < buf_len)
        buf[off++] = ',';
    int n = snprintf(buf + off, buf_len - off, "\"%s\":%s", key, raw_value);
    if (n > 0) off += (size_t)n;
    buf[off] = '\0';
    *offset = off;
}

/**
 * Build a response JSON object in buf. Returns buf for convenience.
 */
static char* build_response(char* buf, size_t buf_len,
                            const char* request_id,
                            const char* payload_json)
{
    size_t off = 0;
    buf[off++] = '{';
    buf[off] = '\0';
    json_append_string(buf, buf_len, &off, "id", request_id, 1);
    json_append_string(buf, buf_len, &off, "type", "response", 0);
    json_append_raw(buf, buf_len, &off, "payload", payload_json, 0);
    if (off + 1 < buf_len)
        buf[off++] = '}';
    buf[off] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Request dispatch                                                   */
/* ------------------------------------------------------------------ */

static void handle_status(const char* request_id)
{
    RootHeraldDeviceStatus status;
    memset(&status, 0, sizeof(status));
    RootHeraldResult result = RootHeraldGetStatus(&status);

    char payload[2048];
    size_t off = 0;
    payload[off++] = '{';
    payload[off] = '\0';
    json_append_raw(payload, sizeof(payload), &off, "success",
                    (result == RH_PROTO_OK) ? "true" : "false", 1);

    /* Build data sub-object */
    char data[1024];
    size_t doff = 0;
    data[doff++] = '{';
    data[doff] = '\0';
    json_append_string(data, sizeof(data), &doff, "status",
                       status.is_enrolled ? "enrolled" : "not_enrolled", 1);
    json_append_string(data, sizeof(data), &doff, "deviceId", status.device_id, 0);
    json_append_string(data, sizeof(data), &doff, "platform", status.platform, 0);
    json_append_raw(data, sizeof(data), &doff, "hasTpm",
                    status.has_tpm ? "true" : "false", 0);
    if (doff + 1 < sizeof(data))
        data[doff++] = '}';
    data[doff] = '\0';

    json_append_raw(payload, sizeof(payload), &off, "data", data, 0);
    if (off + 1 < sizeof(payload))
        payload[off++] = '}';
    payload[off] = '\0';

    char resp[4096];
    build_response(resp, sizeof(resp), request_id, payload);
    write_message(resp);
}

static void handle_enroll(const char* request_id, const char* server_url)
{
    if (!server_url || server_url[0] == '\0') {
        char payload[256];
        size_t off = 0;
        payload[off++] = '{';
        payload[off] = '\0';
        json_append_raw(payload, sizeof(payload), &off, "success", "false", 1);
        json_append_string(payload, sizeof(payload), &off, "error", "serverUrl is required", 0);
        if (off + 1 < sizeof(payload)) payload[off++] = '}';
        payload[off] = '\0';

        char resp[4096];
        build_response(resp, sizeof(resp), request_id, payload);
        write_message(resp);
        return;
    }

    RootHeraldEnrollmentInfo info;
    memset(&info, 0, sizeof(info));
    RootHeraldResult result = RootHeraldEnroll(server_url, &info);

    char data[256];
    size_t doff = 0;
    data[doff++] = '{';
    data[doff] = '\0';
    json_append_string(data, sizeof(data), &doff, "deviceId", info.device_id, 1);
    if (doff + 1 < sizeof(data)) data[doff++] = '}';
    data[doff] = '\0';

    char payload[1024];
    size_t off = 0;
    payload[off++] = '{';
    payload[off] = '\0';
    json_append_raw(payload, sizeof(payload), &off, "success",
                    (result == RH_PROTO_OK) ? "true" : "false", 1);
    json_append_raw(payload, sizeof(payload), &off, "data", data, 0);
    if (off + 1 < sizeof(payload)) payload[off++] = '}';
    payload[off] = '\0';

    char resp[4096];
    build_response(resp, sizeof(resp), request_id, payload);
    write_message(resp);
}

static void handle_attest(const char* request_id, const char* server_url,
                          const char* session_id, const char* nonce)
{
    if (!server_url || server_url[0] == '\0' ||
        !session_id || session_id[0] == '\0' ||
        !nonce || nonce[0] == '\0') {
        char payload[512];
        size_t off = 0;
        payload[off++] = '{';
        payload[off] = '\0';
        json_append_raw(payload, sizeof(payload), &off, "success", "false", 1);
        json_append_string(payload, sizeof(payload), &off, "error",
                           "serverUrl, sessionId, and nonce are required", 0);
        if (off + 1 < sizeof(payload)) payload[off++] = '}';
        payload[off] = '\0';

        char resp[4096];
        build_response(resp, sizeof(resp), request_id, payload);
        write_message(resp);
        return;
    }

    RootHeraldAttestationInfo info;
    memset(&info, 0, sizeof(info));
    RootHeraldResult result = RootHeraldAttest(
        server_url, session_id, nonce, strlen(nonce), &info);

    char data[4096];
    size_t doff = 0;
    data[doff++] = '{';
    data[doff] = '\0';
    json_append_string(data, sizeof(data), &doff, "authorizationCode",
                       info.authorization_code, 1);
    json_append_string(data, sizeof(data), &doff, "status", info.status, 0);
    json_append_string(data, sizeof(data), &doff, "redirectUri", info.redirect_uri, 0);
    if (doff + 1 < sizeof(data)) data[doff++] = '}';
    data[doff] = '\0';

    char payload[8192];
    size_t off = 0;
    payload[off++] = '{';
    payload[off] = '\0';
    json_append_raw(payload, sizeof(payload), &off, "success",
                    (result == RH_PROTO_OK) ? "true" : "false", 1);
    json_append_raw(payload, sizeof(payload), &off, "data", data, 0);
    json_append_string(payload, sizeof(payload), &off, "error",
                       info.failure_reason, 0);
    if (off + 1 < sizeof(payload)) payload[off++] = '}';
    payload[off] = '\0';

    char resp[16384];
    build_response(resp, sizeof(resp), request_id, payload);
    write_message(resp);
}

static void handle_unknown(const char* request_id, const char* action)
{
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "Unknown action: %s",
             action ? action : "(null)");

    char payload[512];
    size_t off = 0;
    payload[off++] = '{';
    payload[off] = '\0';
    json_append_raw(payload, sizeof(payload), &off, "success", "false", 1);
    json_append_string(payload, sizeof(payload), &off, "error", error_msg, 0);
    if (off + 1 < sizeof(payload)) payload[off++] = '}';
    payload[off] = '\0';

    char resp[4096];
    build_response(resp, sizeof(resp), request_id, payload);
    write_message(resp);
}

/* ------------------------------------------------------------------ */
/*  Main loop                                                          */
/* ------------------------------------------------------------------ */

int main(void)
{
    while (1) {
        char* request = read_message();
        if (!request) break;

        /* Parse fields from the incoming JSON request */
        char action[64]     = "";
        char server_url[2048] = "";
        char request_id[64] = "";
        char session_id[64] = "";
        char nonce[4096]    = "";

        json_get(request, "action",    action,     sizeof(action));
        json_get(request, "serverUrl", server_url, sizeof(server_url));
        json_get(request, "id",        request_id, sizeof(request_id));
        json_get(request, "sessionId", session_id, sizeof(session_id));
        json_get(request, "nonce",     nonce,      sizeof(nonce));

        /* Dispatch */
        if (strcmp(action, "status") == 0) {
            handle_status(request_id);
        } else if (strcmp(action, "enroll") == 0) {
            handle_enroll(request_id, server_url);
        } else if (strcmp(action, "attest") == 0) {
            handle_attest(request_id, server_url, session_id, nonce);
        } else {
            handle_unknown(request_id, action);
        }

        free(request);
    }

    return 0;
}
