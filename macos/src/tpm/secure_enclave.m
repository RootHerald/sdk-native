/**
 * Apple Secure Enclave wrapper — Implementation
 */

#import "secure_enclave.h"

static NSString* const kDeviceKeyTag = @"com.rootherald.device-key";

@implementation RootHeraldSecureEnclave

+ (BOOL)isAvailable
{
    /* Secure Enclave is available on all Apple Silicon Macs
       and Intel Macs with T2 chip. */
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        nil);

    if (!access) return NO;
    CFRelease(access);
    return YES;
}

- (SecKeyRef _Nullable)getOrCreateDeviceKey:(NSError **)error
{
    /* Try to find existing key first */
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrApplicationTag: [kDeviceKeyTag dataUsingEncoding:NSUTF8StringEncoding],
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecReturnRef: @YES,
    };

    SecKeyRef existingKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&existingKey);
    if (status == errSecSuccess && existingKey) {
        return existingKey;
    }

    /* Create new key in Secure Enclave */
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        nil);

    if (!access) {
        if (error) *error = [NSError errorWithDomain:@"RootHeraldSecureEnclave"
                                                code:-1
                                            userInfo:@{NSLocalizedDescriptionKey: @"Failed to create access control"}];
        return nil;
    }

    NSDictionary *attributes = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent: @YES,
            (id)kSecAttrApplicationTag: [kDeviceKeyTag dataUsingEncoding:NSUTF8StringEncoding],
            (id)kSecAttrAccessControl: (__bridge id)access,
        },
    };

    CFErrorRef cfError = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &cfError);
    CFRelease(access);

    if (!privateKey) {
        if (error && cfError) *error = (__bridge_transfer NSError *)cfError;
        return nil;
    }

    return privateKey;
}

- (NSData * _Nullable)exportPublicKey:(SecKeyRef)privateKey error:(NSError **)error
{
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    if (!publicKey) {
        if (error) *error = [NSError errorWithDomain:@"RootHeraldSecureEnclave"
                                                code:-2
                                            userInfo:@{NSLocalizedDescriptionKey: @"Failed to copy public key"}];
        return nil;
    }

    CFErrorRef cfError = NULL;
    CFDataRef pubKeyData = SecKeyCopyExternalRepresentation(publicKey, &cfError);
    CFRelease(publicKey);

    if (!pubKeyData) {
        if (error && cfError) *error = (__bridge_transfer NSError *)cfError;
        return nil;
    }

    return (__bridge_transfer NSData *)pubKeyData;
}

- (NSData * _Nullable)sign:(NSData *)data
            withPrivateKey:(SecKeyRef)privateKey
                     error:(NSError **)error
{
    CFErrorRef cfError = NULL;
    CFDataRef signature = SecKeyCreateSignature(
        privateKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)data,
        &cfError);

    if (!signature) {
        if (error && cfError) *error = (__bridge_transfer NSError *)cfError;
        return nil;
    }

    return (__bridge_transfer NSData *)signature;
}

@end
