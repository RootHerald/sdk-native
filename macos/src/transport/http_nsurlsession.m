/**
 * HTTP transport using NSURLSession — Implementation
 *
 * Provides synchronous wrappers around NSURLSession's async API
 * using dispatch_semaphore for blocking.
 */

#import "http_nsurlsession.h"

static NSString* const kUserAgent = @"RootHerald/1.0 (macOS)";
static const NSTimeInterval kRequestTimeout = 30.0;

/**
 * Internal helper: perform a synchronous HTTP request and return parsed JSON.
 */
static NSDictionary* DoRequest(NSString* method,
                               NSString* urlString,
                               NSDictionary* jsonBody,
                               NSInteger* outStatusCode,
                               NSError** error)
{
    NSURL* url = [NSURL URLWithString:urlString];
    if (!url) {
        if (error) {
            *error = [NSError errorWithDomain:@"RootHeraldHTTP"
                                         code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid URL"}];
        }
        return nil;
    }

    NSMutableURLRequest* request = [NSMutableURLRequest requestWithURL:url];
    [request setHTTPMethod:method];
    [request setValue:kUserAgent forHTTPHeaderField:@"User-Agent"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [request setTimeoutInterval:kRequestTimeout];

    if (jsonBody) {
        NSError* serializationError = nil;
        NSData* bodyData = [NSJSONSerialization dataWithJSONObject:jsonBody
                                                           options:0
                                                             error:&serializationError];
        if (!bodyData) {
            if (error) *error = serializationError;
            return nil;
        }
        [request setHTTPBody:bodyData];
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }

    __block NSData* responseData = nil;
    __block NSURLResponse* urlResponse = nil;
    __block NSError* taskError = nil;

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);

    NSURLSession* session = [NSURLSession sharedSession];
    NSURLSessionDataTask* task = [session dataTaskWithRequest:request
                                           completionHandler:^(NSData* data,
                                                               NSURLResponse* response,
                                                               NSError* err) {
        responseData = data;
        urlResponse = response;
        taskError = err;
        dispatch_semaphore_signal(semaphore);
    }];
    [task resume];

    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

    if (taskError) {
        if (error) *error = taskError;
        return nil;
    }

    NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)urlResponse;
    if (outStatusCode) {
        *outStatusCode = httpResponse.statusCode;
    }

    if (!responseData || responseData.length == 0) {
        /* Some endpoints (e.g. 204 No Content) return empty body */
        return @{};
    }

    NSError* parseError = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:responseData
                                                    options:0
                                                      error:&parseError];
    if (!jsonObject) {
        if (error) *error = parseError;
        return nil;
    }

    if (![jsonObject isKindOfClass:[NSDictionary class]]) {
        if (error) {
            *error = [NSError errorWithDomain:@"RootHeraldHTTP"
                                         code:-2
                                     userInfo:@{NSLocalizedDescriptionKey: @"Response is not a JSON object"}];
        }
        return nil;
    }

    return (NSDictionary*)jsonObject;
}

NSDictionary* HttpPostJson(NSString* url,
                           NSDictionary* jsonBody,
                           NSInteger* outStatusCode,
                           NSError** error)
{
    return DoRequest(@"POST", url, jsonBody, outStatusCode, error);
}

NSDictionary* HttpGetJson(NSString* url,
                          NSInteger* outStatusCode,
                          NSError** error)
{
    return DoRequest(@"GET", url, nil, outStatusCode, error);
}
