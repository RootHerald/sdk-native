/**
 * Internal logging shim (Linux). Not exported to customers. See windows/log.h
 * for the same interface description; the Windows + Linux + macOS variants
 * provide identical signatures behind the same public header.
 */

#ifndef ROOTHERALD_INTERNAL_LOG_H
#define ROOTHERALD_INTERNAL_LOG_H

#include "rootherald.h"

void rh_log(RootHeraldLogLevel level, const char* fmt, ...);

#define RH_LOG_ERROR(...) rh_log(ROOTHERALD_LOG_ERROR, __VA_ARGS__)
#define RH_LOG_WARN(...)  rh_log(ROOTHERALD_LOG_WARN,  __VA_ARGS__)
#define RH_LOG_INFO(...)  rh_log(ROOTHERALD_LOG_INFO,  __VA_ARGS__)
#define RH_LOG_DEBUG(...) rh_log(ROOTHERALD_LOG_DEBUG, __VA_ARGS__)
#define RH_LOG_TRACE(...) rh_log(ROOTHERALD_LOG_TRACE, __VA_ARGS__)

#endif /* ROOTHERALD_INTERNAL_LOG_H */
