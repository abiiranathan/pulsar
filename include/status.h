#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <solidc/str_slice.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : uint32_t {
    StatusContinue = 100,
    StatusSwitchingProtocols = 101,
    StatusProcessing = 102,
    StatusEarlyHints = 103,

    StatusOK = 200,
    StatusCreated = 201,
    StatusAccepted = 202,
    StatusNonAuthoritativeInfo = 203,
    StatusNoContent = 204,
    StatusResetContent = 205,
    StatusPartialContent = 206,
    StatusMultiStatus = 207,
    StatusAlreadyReported = 208,
    StatusIMUsed = 226,

    StatusMultipleChoices = 300,
    StatusMovedPermanently = 301,
    StatusFound = 302,
    StatusSeeOther = 303,
    StatusNotModified = 304,
    StatusUseProxy = 305,
    StatusUnused = 306,
    StatusTemporaryRedirect = 307,
    StatusPermanentRedirect = 308,

    StatusBadRequest = 400,
    StatusUnauthorized = 401,
    StatusPaymentRequired = 402,
    StatusForbidden = 403,
    StatusNotFound = 404,
    StatusMethodNotAllowed = 405,
    StatusNotAcceptable = 406,
    StatusProxyAuthRequired = 407,
    StatusRequestTimeout = 408,
    StatusConflict = 409,
    StatusGone = 410,
    StatusLengthRequired = 411,
    StatusPreconditionFailed = 412,
    StatusRequestEntityTooLarge = 413,
    StatusRequestURITooLong = 414,
    StatusUnsupportedMediaType = 415,
    StatusRequestedRangeNotSatisfiable = 416,
    StatusExpectationFailed = 417,
    StatusTeapot = 418,
    StatusMisdirectedRequest = 421,
    StatusUnprocessableEntity = 422,
    StatusLocked = 423,
    StatusFailedDependency = 424,
    StatusTooEarly = 425,
    StatusUpgradeRequired = 426,
    StatusPreconditionRequired = 428,
    StatusTooManyRequests = 429,
    StatusRequestHeaderFieldsTooLarge = 431,
    StatusUnavailableForLegalReasons = 451,

    StatusInternalServerError = 500,
    StatusNotImplemented = 501,
    StatusBadGateway = 502,
    StatusServiceUnavailable = 503,
    StatusGatewayTimeout = 504,
    StatusHTTPVersionNotSupported = 505,
    StatusVariantAlsoNegotiates = 506,
    StatusInsufficientStorage = 507,
    StatusLoopDetected = 508,
    StatusNotExtended = 510,
    StatusNetworkAuthenticationRequired = 511
} http_status;

// Lookup table indexed by status code (offset from 100)
#define STATUS_MIN StatusContinue
#define STATUS_MAX StatusNetworkAuthenticationRequired

// Predefined status lines for common HTTP status codes. Indexed by status code.
// Format:
static const StrSlice status_info[512] = {
    [100] = SS_LIT("HTTP/1.1 100 Continue\r\n"),
    [101] = SS_LIT("HTTP/1.1 101 Switching Protocols\r\n"),
    [102] = SS_LIT("HTTP/1.1 102 Processing\r\n"),
    [103] = SS_LIT("HTTP/1.1 103 Early Hints\r\n"),
    [200] = SS_LIT("HTTP/1.1 200 OK\r\n"),
    [201] = SS_LIT("HTTP/1.1 201 Created\r\n"),
    [202] = SS_LIT("HTTP/1.1 202 Accepted\r\n"),
    [203] = SS_LIT("HTTP/1.1 203 Non-Authoritative Information\r\n"),
    [204] = SS_LIT("HTTP/1.1 204 No Content\r\n"),
    [205] = SS_LIT("HTTP/1.1 205 Reset Content\r\n"),
    [206] = SS_LIT("HTTP/1.1 206 Partial Content\r\n"),
    [207] = SS_LIT("HTTP/1.1 207 Multi-Status\r\n"),
    [208] = SS_LIT("HTTP/1.1 208 Already Reported\r\n"),
    [226] = SS_LIT("HTTP/1.1 226 IM Used\r\n"),
    [300] = SS_LIT("HTTP/1.1 300 Multiple Choices\r\n"),
    [301] = SS_LIT("HTTP/1.1 301 Moved Permanently\r\n"),
    [302] = SS_LIT("HTTP/1.1 302 Found\r\n"),
    [303] = SS_LIT("HTTP/1.1 303 See Other\r\n"),
    [304] = SS_LIT("HTTP/1.1 304 Not Modified\r\n"),
    [305] = SS_LIT("HTTP/1.1 305 Use Proxy\r\n"),
    [306] = SS_LIT("HTTP/1.1 306 Unused\r\n"),
    [307] = SS_LIT("HTTP/1.1 307 Temporary Redirect\r\n"),
    [308] = SS_LIT("HTTP/1.1 308 Permanent Redirect\r\n"),
    [400] = SS_LIT("HTTP/1.1 400 Bad Request\r\n"),
    [401] = SS_LIT("HTTP/1.1 401 Unauthorized\r\n"),
    [402] = SS_LIT("HTTP/1.1 402 Payment Required\r\n"),
    [403] = SS_LIT("HTTP/1.1 403 Forbidden\r\n"),
    [404] = SS_LIT("HTTP/1.1 404 Not Found\r\n"),
    [405] = SS_LIT("HTTP/1.1 405 Method Not Allowed\r\n"),
    [406] = SS_LIT("HTTP/1.1 406 Not Acceptable\r\n"),
    [407] = SS_LIT("HTTP/1.1 407 Proxy Authentication Required\r\n"),
    [408] = SS_LIT("HTTP/1.1 408 Request Timeout\r\n"),
    [409] = SS_LIT("HTTP/1.1 409 Conflict\r\n"),
    [410] = SS_LIT("HTTP/1.1 410 Gone\r\n"),
    [411] = SS_LIT("HTTP/1.1 411 Length Required\r\n"),
    [412] = SS_LIT("HTTP/1.1 412 Precondition Failed\r\n"),
    [413] = SS_LIT("HTTP/1.1 413 Request Entity Too Large\r\n"),
    [414] = SS_LIT("HTTP/1.1 414 Request URI Too Long\r\n"),
    [415] = SS_LIT("HTTP/1.1 415 Unsupported Media Type\r\n"),
    [416] = SS_LIT("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
    [417] = SS_LIT("HTTP/1.1 417 Expectation Failed\r\n"),
    [418] = SS_LIT("HTTP/1.1 418 I'm a teapot\r\n"),
    [421] = SS_LIT("HTTP/1.1 421 Misdirected Request\r\n"),
    [422] = SS_LIT("HTTP/1.1 422 Unprocessable Entity\r\n"),
    [423] = SS_LIT("HTTP/1.1 423 Locked\r\n"),
    [424] = SS_LIT("HTTP/1.1 424 Failed Dependency\r\n"),
    [425] = SS_LIT("HTTP/1.1 425 Too Early\r\n"),
    [426] = SS_LIT("HTTP/1.1 426 Upgrade Required\r\n"),
    [428] = SS_LIT("HTTP/1.1 428 Precondition Required\r\n"),
    [429] = SS_LIT("HTTP/1.1 429 Too Many Requests\r\n"),
    [431] = SS_LIT("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
    [451] = SS_LIT("HTTP/1.1 451 Unavailable For Legal Reasons\r\n"),
    [500] = SS_LIT("HTTP/1.1 500 Internal Server Error\r\n"),
    [501] = SS_LIT("HTTP/1.1 501 Not Implemented\r\n"),
    [502] = SS_LIT("HTTP/1.1 502 Bad Gateway\r\n"),
    [503] = SS_LIT("HTTP/1.1 503 Service Unavailable\r\n"),
    [504] = SS_LIT("HTTP/1.1 504 Gateway Timeout\r\n"),
    [505] = SS_LIT("HTTP/1.1 505 HTTP Version Not Supported\r\n"),
    [506] = SS_LIT("HTTP/1.1 506 Variant Also Negotiates\r\n"),
    [507] = SS_LIT("HTTP/1.1 507 Insufficient Storage\r\n"),
    [508] = SS_LIT("HTTP/1.1 508 Loop Detected\r\n"),
    [510] = SS_LIT("HTTP/1.1 510 Not Extended\r\n"),
    [511] = SS_LIT("HTTP/1.1 511 Network Authentication Required\r\n"),
};

INLINE bool http_status_valid(http_status code) {
    return (code >= STATUS_MIN && code <= STATUS_MAX);
}

// Direct lookup using status code as index
INLINE StrSlice get_http_status(http_status code) {
    if (!http_status_valid(code)) { return SS_LIT("HTTP/1.1 200 OK\r\n"); }
    return status_info[code];
}

#ifdef __cplusplus
}
#endif

#endif /* STATUS_CODE_H */
