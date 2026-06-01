/**
 * TCG Event Log reader for Linux.
 * Reads from /sys/kernel/security/tpm0/binary_bios_measurements.
 */

#ifndef ROOTHERALD_EVENT_LOG_LINUX_H
#define ROOTHERALD_EVENT_LOG_LINUX_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Read the BIOS event log into a caller-provided buffer.
 * Returns bytes read, or -1 on error.
 * If buf is NULL, returns the required buffer size.
 */
int event_log_read(uint8_t* buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* ROOTHERALD_EVENT_LOG_LINUX_H */
