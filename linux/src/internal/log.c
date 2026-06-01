/**
 * Root Herald native SDK — logging shim (Linux).
 *
 * Single global callback + level filter. NULL callback = silent (default).
 * See log.h for usage; INTEGRATING.md for the customer-facing rationale.
 */

#include "rootherald.h"
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static RootHeraldLogCallback g_log_callback = NULL;
static void* g_log_user_data = NULL;
static RootHeraldLogLevel g_log_max_level = ROOTHERALD_LOG_WARN;

void RootHerald_SetLogCallback(
    RootHeraldLogCallback callback,
    void* user_data)
{
    g_log_callback = callback;
    g_log_user_data = user_data;
}

void RootHerald_SetLogLevel(RootHeraldLogLevel max_level)
{
    g_log_max_level = max_level;
}

void rh_log(RootHeraldLogLevel level, const char* fmt, ...)
{
    if (g_log_callback == NULL) return;
    if ((int)level > (int)g_log_max_level) return;

    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0) {
        snprintf(buf, sizeof(buf), "(log message formatting failed)");
    }
    /* Trim trailing newline. */
    size_t len = strnlen(buf, sizeof(buf));
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }

    g_log_callback(level, buf, g_log_user_data);
}

const char* RootHerald_ErrorString(RootHeraldStatus status)
{
    switch (status) {
        case ROOTHERALD_OK:                  return "ok";
        case ROOTHERALD_ERR_INVALID_ARG:     return "invalid argument";
        case ROOTHERALD_ERR_TPM_UNAVAILABLE: return "TPM unavailable on this host";
        case ROOTHERALD_ERR_NETWORK:         return "network error reaching the Root Herald endpoint";
        case ROOTHERALD_ERR_SERVER:          return "Root Herald server returned an error";
        case ROOTHERALD_ERR_QUOTA_EXCEEDED:  return "tenant quota exceeded";
        case ROOTHERALD_ERR_INTERNAL:        return "internal library error";
        default:                             return "unknown error";
    }
}
