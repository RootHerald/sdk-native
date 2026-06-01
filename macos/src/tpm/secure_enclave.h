/**
 * Apple Secure Enclave wrapper for key generation and signing.
 */

#ifndef ROOTHERALD_SECURE_ENCLAVE_H
#define ROOTHERALD_SECURE_ENCLAVE_H

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface RootHeraldSecureEnclave : NSObject

/// Check if Secure Enclave is available on this device.
+ (BOOL)isAvailable;

/// Generate or retrieve the device attestation key (ECC P-256).
/// Returns the SecKeyRef for the private key, or nil on failure.
- (SecKeyRef _Nullable)getOrCreateDeviceKey:(NSError **)error;

/// Export the public key as uncompressed SEC1/X9.63 data.
- (NSData * _Nullable)exportPublicKey:(SecKeyRef)privateKey error:(NSError **)error;

/// Sign data with the Secure Enclave key using ECDSA SHA-256.
- (NSData * _Nullable)sign:(NSData *)data
            withPrivateKey:(SecKeyRef)privateKey
                     error:(NSError **)error;

@end

#endif /* ROOTHERALD_SECURE_ENCLAVE_H */
