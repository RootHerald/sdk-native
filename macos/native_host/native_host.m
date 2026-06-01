/**
 *  Root Herald Native Messaging Host — macOS
 *
 * Bridges browser extension requests to the  Root Herald client SDK
 * via Chrome/Edge/Firefox native messaging protocol (length-prefixed JSON on stdin/stdout).
 */

#import "rootherald_macos.h"
#import <Foundation/Foundation.h>
#import <stdio.h>
#import <stdint.h>
#import <string.h>

/* -------------------------------------------------------------------------- */
/*  Native Messaging I/O                                                       */
/* -------------------------------------------------------------------------- */

static NSData* ReadMessageData(void)
{
    uint32_t length = 0;
    if (fread(&length, sizeof(length), 1, stdin) != 1)
        return nil;

    if (length > 1024 * 1024) /* 1 MB limit */
        return nil;

    NSMutableData* buffer = [NSMutableData dataWithLength:length];
    if (!buffer) return nil;

    if (fread(buffer.mutableBytes, 1, length, stdin) != length)
        return nil;

    return buffer;
}

static void WriteResponse(NSDictionary* response)
{
    NSError* error = nil;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:response
                                                       options:0
                                                         error:&error];
    if (!jsonData) {
        /* Fallback error message */
        const char* fallback = "{\"success\":false,\"error\":\"JSON serialization failed\"}";
        uint32_t len = (uint32_t)strlen(fallback);
        fwrite(&len, sizeof(len), 1, stdout);
        fwrite(fallback, 1, len, stdout);
        fflush(stdout);
        return;
    }

    uint32_t length = (uint32_t)jsonData.length;
    fwrite(&length, sizeof(length), 1, stdout);
    fwrite(jsonData.bytes, 1, length, stdout);
    fflush(stdout);
}

/* -------------------------------------------------------------------------- */
/*  Action Handlers                                                            */
/* -------------------------------------------------------------------------- */

static NSDictionary* HandleStatus(NSString* requestId)
{
    RootHeraldDeviceStatus status = {};
    RootHeraldResult result = RootHeraldGetStatus(&status);

    NSDictionary* data = @{
        @"status":   status.is_enrolled ? @"enrolled" : @"not_enrolled",
        @"deviceId": [NSString stringWithUTF8String:status.device_id],
        @"platform": [NSString stringWithUTF8String:status.platform],
        @"hasTpm":   @(status.has_tpm != 0)
    };

    NSDictionary* payload = @{
        @"success": @(result == RH_PROTO_OK),
        @"data":    data
    };

    return @{
        @"id":      requestId ?: @"",
        @"type":    @"response",
        @"payload": payload
    };
}

static NSDictionary* HandleEnroll(NSString* requestId, NSString* serverUrl)
{
    if (!serverUrl || serverUrl.length == 0) {
        return @{
            @"id":      requestId ?: @"",
            @"type":    @"response",
            @"payload": @{
                @"success": @NO,
                @"error":   @"serverUrl is required"
            }
        };
    }

    RootHeraldEnrollmentInfo info = {};
    RootHeraldResult result = RootHeraldEnroll([serverUrl UTF8String], /*force_reenroll=*/0, &info);

    NSDictionary* data = @{
        @"deviceId": [NSString stringWithUTF8String:info.device_id]
    };

    NSDictionary* payload = @{
        @"success": @(result == RH_PROTO_OK),
        @"data":    data
    };

    return @{
        @"id":      requestId ?: @"",
        @"type":    @"response",
        @"payload": payload
    };
}

static NSDictionary* HandleAttest(NSString* requestId,
                                  NSString* serverUrl,
                                  NSString* sessionId,
                                  NSString* nonce)
{
    if (!serverUrl || serverUrl.length == 0 ||
        !sessionId || sessionId.length == 0 ||
        !nonce     || nonce.length == 0) {
        return @{
            @"id":      requestId ?: @"",
            @"type":    @"response",
            @"payload": @{
                @"success": @NO,
                @"error":   @"serverUrl, sessionId, and nonce are required"
            }
        };
    }

    RootHeraldAttestationInfo info = {};
    RootHeraldResult result = RootHeraldAttest(
        [serverUrl UTF8String],
        [sessionId UTF8String],
        [nonce UTF8String],
        nonce.length,
        &info);

    NSDictionary* data = @{
        @"authorizationCode": [NSString stringWithUTF8String:info.authorization_code],
        @"status":            [NSString stringWithUTF8String:info.status],
        @"redirectUri":       [NSString stringWithUTF8String:info.redirect_uri]
    };

    NSMutableDictionary* payload = [NSMutableDictionary dictionaryWithDictionary:@{
        @"success": @(result == RH_PROTO_OK),
        @"data":    data
    }];

    NSString* failureReason = [NSString stringWithUTF8String:info.failure_reason];
    if (failureReason.length > 0) {
        payload[@"error"] = failureReason;
    }

    return @{
        @"id":      requestId ?: @"",
        @"type":    @"response",
        @"payload": [payload copy]
    };
}

/* -------------------------------------------------------------------------- */
/*  Request Dispatch                                                           */
/* -------------------------------------------------------------------------- */

static NSDictionary* HandleRequest(NSDictionary* request)
{
    NSString* action    = request[@"action"];
    NSString* serverUrl = request[@"serverUrl"];
    NSString* requestId = request[@"id"] ?: @"";

    if ([action isEqualToString:@"status"]) {
        return HandleStatus(requestId);
    }
    else if ([action isEqualToString:@"enroll"]) {
        return HandleEnroll(requestId, serverUrl);
    }
    else if ([action isEqualToString:@"attest"]) {
        NSString* sessionId = request[@"sessionId"];
        NSString* nonce     = request[@"nonce"];
        return HandleAttest(requestId, serverUrl, sessionId, nonce);
    }

    return @{
        @"id":      requestId,
        @"type":    @"response",
        @"payload": @{
            @"success": @NO,
            @"error":   [NSString stringWithFormat:@"Unknown action: %@", action ?: @"(nil)"]
        }
    };
}

/* -------------------------------------------------------------------------- */
/*  Main                                                                       */
/* -------------------------------------------------------------------------- */

int main(void)
{
    @autoreleasepool {
        while (YES) {
            NSData* messageData = ReadMessageData();
            if (!messageData) break;

            /* Parse JSON from stdin */
            NSError* parseError = nil;
            id jsonObject = [NSJSONSerialization JSONObjectWithData:messageData
                                                            options:0
                                                              error:&parseError];

            if (!jsonObject || ![jsonObject isKindOfClass:[NSDictionary class]]) {
                WriteResponse(@{
                    @"id":      @"",
                    @"type":    @"response",
                    @"payload": @{
                        @"success": @NO,
                        @"error":   @"Invalid JSON request"
                    }
                });
                continue;
            }

            NSDictionary* request = (NSDictionary*)jsonObject;
            NSDictionary* response = HandleRequest(request);
            WriteResponse(response);
        }
    }
    return 0;
}
