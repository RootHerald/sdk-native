/**
 * TCG Event Log reader — Linux implementation
 */

#include "event_log.h"

#include <stdio.h>
#include <stdlib.h>

static const char* EVENT_LOG_PATH =
    "/sys/kernel/security/tpm0/binary_bios_measurements";

int event_log_read(uint8_t* buf, size_t buf_len)
{
    FILE* f = fopen(EVENT_LOG_PATH, "rb");
    if (!f) return -1;

    if (!buf) {
        /* Determine size */
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fclose(f);
        return (int)size;
    }

    size_t bytes_read = fread(buf, 1, buf_len, f);
    fclose(f);
    return (int)bytes_read;
}
