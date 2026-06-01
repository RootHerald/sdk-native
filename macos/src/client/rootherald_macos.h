/**
 *  Root Herald macOS Client SDK
 *
 * Uses Security.framework Secure Enclave for key attestation.
 * NOTE: macOS has no TPM — this provides reduced-assurance attestation only.
 * No PCRs, no Quote, no event log. Only key-attestation (proving a key
 * is hardware-bound in the Secure Enclave).
 */

#ifndef ROOTHERALD_MACOS_H
#define ROOTHERALD_MACOS_H

#include "protocol.h"

RootHeraldResult RootHeraldEnroll(
    const char* server_url,
    int force_reenroll,
    RootHeraldEnrollmentInfo* out_info
);

RootHeraldResult RootHeraldAttest(
    const char* server_url,
    const char* session_id,
    const char* nonce_b64,
    size_t nonce_len,
    RootHeraldAttestationInfo* out_info
);

RootHeraldResult RootHeraldGetStatus(
    RootHeraldDeviceStatus* out_status
);

#endif /* ROOTHERALD_MACOS_H */
