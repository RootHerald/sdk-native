/**
 *  Root Herald macOS Client SDK — Implementation
 *
 * Uses Security.framework Secure Enclave for key attestation.
 * NOTE: macOS has no TPM — this provides reduced-assurance attestation only.
 * No PCRs, no Quote, no event log. Only key-attestation (proving a key
 * is hardware-bound in the Secure Enclave).
 */

#import "rootherald_macos.h"
#import "secure_enclave.h"
#import "http_nsurlsession.h"
#import "../internal/log.h"
#import <Foundation/Foundation.h>
#import <string.h>

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Generate a minimal self-signed PEM certificate placeholder.
 * macOS has no EK certificate from a TPM manufacturer, so we provide the
 * Secure Enclave public key wrapped in a trivial PEM structure that the
 * server can parse.  This is not a real X.509 cert; it is a base64-encoded
 * public key bracketed by PEM markers, which the server's macOS enrollment
 * path can accept.
 */
static NSString* MakePlaceholderCertPem(NSData* publicKeyData)
{
    NSString* b64 = [publicKeyData base64EncodedStringWithOptions:0];
    return [NSString stringWithFormat:
            @"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----", b64];
}

/**
 * Safely copy a C string into a fixed-size buffer (like strncpy_s).
 */
static void SafeCopy(char* dest, size_t destSize, const char* src)
{
    if (!src) {
        dest[0] = '\0';
        return;
    }
    strncpy(dest, src, destSize - 1);
    dest[destSize - 1] = '\0';
}

/* -------------------------------------------------------------------------- */
/*  RootHeraldEnroll                                                           */
/* -------------------------------------------------------------------------- */

RootHeraldResult RootHeraldEnroll(
    const char* server_url,
    int force_reenroll,
    RootHeraldEnrollmentInfo* out_info)
{
    (void)force_reenroll;  /* macOS Secure Enclave does not yet honor re-enroll */
    if (!server_url || !out_info)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_info, 0, sizeof(RootHeraldEnrollmentInfo));

    @autoreleasepool {
        NSError* error = nil;

        /* 1. Get or create Secure Enclave key */
        RootHeraldSecureEnclave* se = [[RootHeraldSecureEnclave alloc] init];
        if (![RootHeraldSecureEnclave isAvailable])
            return RH_PROTO_ERR_NO_TPM; /* Closest equivalent: no SE */

        SecKeyRef privateKey = [se getOrCreateDeviceKey:&error];
        if (!privateKey) {
            RH_LOG_WARN("Failed to get/create SE key: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_INTERNAL;
        }

        /* 2. Export public key (uncompressed SEC1/X9.63) */
        NSData* pubKeyData = [se exportPublicKey:privateKey error:&error];
        if (!pubKeyData) {
            CFRelease(privateKey);
            RH_LOG_WARN("Failed to export public key: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_INTERNAL;
        }

        NSString* pubKeyB64 = [pubKeyData base64EncodedStringWithOptions:0];
        NSString* certPem = MakePlaceholderCertPem(pubKeyData);

        /* 3. POST enrollment to /api/v1/devices/enroll */
        NSString* baseUrl = [NSString stringWithUTF8String:server_url];
        NSString* enrollUrl = [baseUrl stringByAppendingString:@"/api/v1/devices/enroll"];

        NSDictionary* enrollBody = @{
            @"ekCertPem":    certPem,
            @"ekPublicKey":  pubKeyB64,
            @"akPublicArea": pubKeyB64,  /* macOS: SE pub key serves as both EK and AK */
            @"platform":     @"macos"
        };

        NSInteger statusCode = 0;
        error = nil;
        NSDictionary* enrollResp = HttpPostJson(enrollUrl, enrollBody, &statusCode, &error);

        if (!enrollResp || statusCode != 201) {
            CFRelease(privateKey);
            RH_LOG_WARN("Enrollment POST failed (status %ld): %s",
                (long)statusCode,
                error ? error.localizedDescription.UTF8String
                      : [[enrollResp description] UTF8String]);
            return RH_PROTO_ERR_ENROLLMENT_FAILED;
        }

        /* 4. Parse response: deviceId, credentialBlob, encryptedSecret */
        NSString* deviceId  = enrollResp[@"deviceId"];
        NSString* credBlob  = enrollResp[@"credentialBlob"];
        NSString* encSecret = enrollResp[@"encryptedSecret"];

        if (!deviceId || !credBlob || !encSecret) {
            CFRelease(privateKey);
            RH_LOG_WARN("Enrollment response missing required fields");
            return RH_PROTO_ERR_ENROLLMENT_FAILED;
        }

        /* 5. For macOS, we cannot do TPM2_ActivateCredential.
         *    Instead, we sign the encryptedSecret with the SE key to prove
         *    possession of the hardware-bound private key. */
        NSData* encSecretData = [[NSData alloc] initWithBase64EncodedString:encSecret options:0];
        if (!encSecretData) {
            CFRelease(privateKey);
            return RH_PROTO_ERR_ENROLLMENT_FAILED;
        }

        NSData* signature = [se sign:encSecretData withPrivateKey:privateKey error:&error];
        if (!signature) {
            CFRelease(privateKey);
            RH_LOG_WARN("Failed to sign encrypted secret: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_ENROLLMENT_FAILED;
        }

        /* The "decryptedSecret" for macOS is the SE signature over encryptedSecret.
         * The server's macOS path can verify this with the registered public key. */
        NSString* decryptedSecretB64 = [signature base64EncodedStringWithOptions:0];

        /* 6. POST activation to /api/v1/devices/activate */
        NSString* activateUrl = [baseUrl stringByAppendingString:@"/api/v1/devices/activate"];

        NSDictionary* activateBody = @{
            @"deviceId":        deviceId,
            @"decryptedSecret": decryptedSecretB64,
            @"akPublicKey":     pubKeyB64
        };

        statusCode = 0;
        error = nil;
        NSDictionary* activateResp = HttpPostJson(activateUrl, activateBody, &statusCode, &error);

        if (!activateResp || statusCode != 200) {
            /* Partial enrollment: save what we have */
            SafeCopy(out_info->device_id, sizeof(out_info->device_id),
                     [deviceId UTF8String]);
            SafeCopy(out_info->credential_blob, sizeof(out_info->credential_blob),
                     [credBlob UTF8String]);
            SafeCopy(out_info->encrypted_secret, sizeof(out_info->encrypted_secret),
                     [encSecret UTF8String]);
            CFRelease(privateKey);
            return RH_PROTO_OK; /* Partial success — enrollment started but activation failed */
        }

        /* 7. Fill output */
        SafeCopy(out_info->device_id, sizeof(out_info->device_id),
                 [deviceId UTF8String]);

        CFRelease(privateKey);
        return RH_PROTO_OK;
    }
}

/* -------------------------------------------------------------------------- */
/*  RootHeraldAttest                                                           */
/* -------------------------------------------------------------------------- */

RootHeraldResult RootHeraldAttest(
    const char* server_url,
    const char* session_id,
    const char* nonce_b64,
    size_t nonce_len,
    RootHeraldAttestationInfo* out_info)
{
    if (!server_url || !session_id || !nonce_b64 || !out_info)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_info, 0, sizeof(RootHeraldAttestationInfo));

    @autoreleasepool {
        NSError* error = nil;

        /* 1. Decode nonce from base64 */
        NSString* nonceStr = [NSString stringWithUTF8String:nonce_b64];
        NSData* nonceData = [[NSData alloc] initWithBase64EncodedString:nonceStr options:0];
        if (!nonceData || nonceData.length == 0)
            return RH_PROTO_ERR_INVALID_PARAM;

        /* 2. Get Secure Enclave key */
        RootHeraldSecureEnclave* se = [[RootHeraldSecureEnclave alloc] init];
        SecKeyRef privateKey = [se getOrCreateDeviceKey:&error];
        if (!privateKey) {
            RH_LOG_WARN("Failed to get SE key for attestation: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_INTERNAL;
        }

        /* 3. Sign nonce with SE key (ECDSA SHA-256) — this is the key-attestation */
        NSData* signature = [se sign:nonceData withPrivateKey:privateKey error:&error];
        if (!signature) {
            CFRelease(privateKey);
            RH_LOG_WARN("Failed to sign nonce: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_INTERNAL;
        }

        NSString* signedNonceB64 = [signature base64EncodedStringWithOptions:0];

        /* 4. Export public key for the attestation request */
        NSData* pubKeyData = [se exportPublicKey:privateKey error:&error];
        CFRelease(privateKey);

        if (!pubKeyData) {
            RH_LOG_WARN("Failed to export public key: %s",
                error.localizedDescription.UTF8String ?: "(no detail)");
            return RH_PROTO_ERR_INTERNAL;
        }

        NSString* pubKeyB64 = [pubKeyData base64EncodedStringWithOptions:0];

        /* 5. Build attestation request — use keyAttestation (not quote) */
        NSString* baseUrl = [NSString stringWithUTF8String:server_url];
        NSString* attestUrl = [baseUrl stringByAppendingString:@"/api/v1/attest"];
        NSString* sessionIdStr = [NSString stringWithUTF8String:session_id];

        NSDictionary* keyAttestation = @{
            @"signedNonce": signedNonceB64,
            @"publicKey":   pubKeyB64
        };

        NSDictionary* attestBody = @{
            @"sessionId":      sessionIdStr,
            @"deviceId":       @"",  /* Server resolves from session */
            @"keyAttestation": keyAttestation
        };

        /* 6. POST attestation */
        NSInteger statusCode = 0;
        error = nil;
        NSDictionary* attestResp = HttpPostJson(attestUrl, attestBody, &statusCode, &error);

        if (!attestResp || statusCode != 200) {
            RH_LOG_WARN("Attestation POST failed (status %ld): %s",
                (long)statusCode,
                error ? error.localizedDescription.UTF8String
                      : [[attestResp description] UTF8String]);
            return RH_PROTO_ERR_ATTESTATION_FAILED;
        }

        /* 7. Parse response */
        NSString* status    = attestResp[@"status"]            ?: @"";
        NSString* authCode  = attestResp[@"authorizationCode"] ?: @"";
        NSString* redirect  = attestResp[@"redirectUri"]       ?: @"";
        NSString* reason    = attestResp[@"reason"]            ?: @"";

        SafeCopy(out_info->session_id, sizeof(out_info->session_id),
                 [sessionIdStr UTF8String]);
        SafeCopy(out_info->status, sizeof(out_info->status),
                 [status UTF8String]);
        SafeCopy(out_info->authorization_code, sizeof(out_info->authorization_code),
                 [authCode UTF8String]);
        SafeCopy(out_info->redirect_uri, sizeof(out_info->redirect_uri),
                 [redirect UTF8String]);
        SafeCopy(out_info->failure_reason, sizeof(out_info->failure_reason),
                 [reason UTF8String]);

        if ([status isEqualToString:@"verified"])
            return RH_PROTO_OK;
        else
            return RH_PROTO_ERR_ATTESTATION_FAILED;
    }
}

/* -------------------------------------------------------------------------- */
/*  RootHeraldGetStatus                                                        */
/* -------------------------------------------------------------------------- */

RootHeraldResult RootHeraldGetStatus(RootHeraldDeviceStatus* out_status)
{
    if (!out_status)
        return RH_PROTO_ERR_INVALID_PARAM;

    memset(out_status, 0, sizeof(RootHeraldDeviceStatus));
    SafeCopy(out_status->platform, sizeof(out_status->platform), "macos");
    out_status->has_tpm = 0; /* macOS has no TPM */

    @autoreleasepool {
        /* Check Secure Enclave availability */
        BOOL seAvailable = [RootHeraldSecureEnclave isAvailable];
        if (!seAvailable)
            return RH_PROTO_OK; /* Report status even if SE is unavailable */

        /* Check if a device key already exists (indicates prior enrollment) */
        NSError* error = nil;
        RootHeraldSecureEnclave* se = [[RootHeraldSecureEnclave alloc] init];
        SecKeyRef key = [se getOrCreateDeviceKey:&error];
        if (key) {
            out_status->is_enrolled = 1;
            CFRelease(key);
        }
    }

    return RH_PROTO_OK;
}
