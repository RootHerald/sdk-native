/**
 * HTTP transport using NSURLSession.
 */

#ifndef ROOTHERALD_HTTP_NSURLSESSION_H
#define ROOTHERALD_HTTP_NSURLSESSION_H

#import <Foundation/Foundation.h>

/// Synchronous HTTP POST with JSON body. Returns parsed JSON dictionary or nil on failure.
NSDictionary* HttpPostJson(NSString* url, NSDictionary* jsonBody, NSInteger* outStatusCode, NSError** error);

/// Synchronous HTTP GET. Returns parsed JSON dictionary or nil on failure.
NSDictionary* HttpGetJson(NSString* url, NSInteger* outStatusCode, NSError** error);

#endif /* ROOTHERALD_HTTP_NSURLSESSION_H */
