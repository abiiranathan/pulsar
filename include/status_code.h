#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : uint32_t {
    StatusContinue           = 100,
    StatusSwitchingProtocols = 101,
    StatusProcessing         = 102,
    StatusEarlyHints         = 103,

    StatusOK                   = 200,
    StatusCreated              = 201,
    StatusAccepted             = 202,
    StatusNonAuthoritativeInfo = 203,
    StatusNoContent            = 204,
    StatusResetContent         = 205,
    StatusPartialContent       = 206,
    StatusMultiStatus          = 207,
    StatusAlreadyReported      = 208,
    StatusIMUsed               = 226,

    StatusMultipleChoices   = 300,
    StatusMovedPermanently  = 301,
    StatusFound             = 302,
    StatusSeeOther          = 303,
    StatusNotModified       = 304,
    StatusUseProxy          = 305,
    StatusUnused            = 306,
    StatusTemporaryRedirect = 307,
    StatusPermanentRedirect = 308,

    StatusBadRequest                   = 400,
    StatusUnauthorized                 = 401,
    StatusPaymentRequired              = 402,
    StatusForbidden                    = 403,
    StatusNotFound                     = 404,
    StatusMethodNotAllowed             = 405,
    StatusNotAcceptable                = 406,
    StatusProxyAuthRequired            = 407,
    StatusRequestTimeout               = 408,
    StatusConflict                     = 409,
    StatusGone                         = 410,
    StatusLengthRequired               = 411,
    StatusPreconditionFailed           = 412,
    StatusRequestEntityTooLarge        = 413,
    StatusRequestURITooLong            = 414,
    StatusUnsupportedMediaType         = 415,
    StatusRequestedRangeNotSatisfiable = 416,
    StatusExpectationFailed            = 417,
    StatusTeapot                       = 418,
    StatusMisdirectedRequest           = 421,
    StatusUnprocessableEntity          = 422,
    StatusLocked                       = 423,
    StatusFailedDependency             = 424,
    StatusTooEarly                     = 425,
    StatusUpgradeRequired              = 426,
    StatusPreconditionRequired         = 428,
    StatusTooManyRequests              = 429,
    StatusRequestHeaderFieldsTooLarge  = 431,
    StatusUnavailableForLegalReasons   = 451,

    StatusInternalServerError           = 500,
    StatusNotImplemented                = 501,
    StatusBadGateway                    = 502,
    StatusServiceUnavailable            = 503,
    StatusGatewayTimeout                = 504,
    StatusHTTPVersionNotSupported       = 505,
    StatusVariantAlsoNegotiates         = 506,
    StatusInsufficientStorage           = 507,
    StatusLoopDetected                  = 508,
    StatusNotExtended                   = 510,
    StatusNetworkAuthenticationRequired = 511
} http_status;

typedef struct {
    const char* text;
    uint8_t length;
} status_info_t;

// Lookup table indexed by status code (offset from 100)
#define STATUS_MIN        StatusContinue
#define STATUS_MAX        StatusNetworkAuthenticationRequired
#define STATUS_TABLE_SIZE (STATUS_MAX - STATUS_MIN + 1)

static const status_info_t status_info[STATUS_TABLE_SIZE] = {
    [0]   = {"Continue", 8},                          // 100
    [1]   = {"Switching Protocols", 19},              // 101
    [2]   = {"Processing", 10},                       // 102
    [3]   = {"Early Hints", 11},                      // 103
    [100] = {"OK", 2},                                // 200
    [101] = {"Created", 7},                           // 201
    [102] = {"Accepted", 8},                          // 202
    [103] = {"Non-Authoritative Information", 29},    // 203
    [104] = {"No Content", 10},                       // 204
    [105] = {"Reset Content", 13},                    // 205
    [106] = {"Partial Content", 15},                  // 206
    [107] = {"Multi-Status", 12},                     // 207
    [108] = {"Already Reported", 16},                 // 208
    [126] = {"IM Used", 7},                           // 226
    [200] = {"Multiple Choices", 16},                 // 300
    [201] = {"Moved Permanently", 17},                // 301
    [202] = {"Found", 5},                             // 302
    [203] = {"See Other", 9},                         // 303
    [204] = {"Not Modified", 12},                     // 304
    [205] = {"Use Proxy", 9},                         // 305
    [206] = {"Unused", 6},                            // 306
    [207] = {"Temporary Redirect", 18},               // 307
    [208] = {"Permanent Redirect", 18},               // 308
    [300] = {"Bad Request", 11},                      // 400
    [301] = {"Unauthorized", 12},                     // 401
    [302] = {"Payment Required", 16},                 // 402
    [303] = {"Forbidden", 9},                         // 403
    [304] = {"Not Found", 9},                         // 404
    [305] = {"Method Not Allowed", 18},               // 405
    [306] = {"Not Acceptable", 14},                   // 406
    [307] = {"Proxy Authentication Required", 29},    // 407
    [308] = {"Request Timeout", 15},                  // 408
    [309] = {"Conflict", 8},                          // 409
    [310] = {"Gone", 4},                              // 410
    [311] = {"Length Required", 15},                  // 411
    [312] = {"Precondition Failed", 19},              // 412
    [313] = {"Request Entity Too Large", 24},         // 413
    [314] = {"Request URI Too Long", 20},             // 414
    [315] = {"Unsupported Media Type", 22},           // 415
    [316] = {"Requested Range Not Satisfiable", 31},  // 416
    [317] = {"Expectation Failed", 18},               // 417
    [318] = {"I'm a teapot", 12},                     // 418
    [321] = {"Misdirected Request", 19},              // 421
    [322] = {"Unprocessable Entity", 20},             // 422
    [323] = {"Locked", 6},                            // 423
    [324] = {"Failed Dependency", 17},                // 424
    [325] = {"Too Early", 9},                         // 425
    [326] = {"Upgrade Required", 16},                 // 426
    [328] = {"Precondition Required", 21},            // 428
    [329] = {"Too Many Requests", 17},                // 429
    [331] = {"Request Header Fields Too Large", 31},  // 431
    [351] = {"Unavailable For Legal Reasons", 29},    // 451
    [400] = {"Internal Server Error", 21},            // 500
    [401] = {"Not Implemented", 15},                  // 501
    [402] = {"Bad Gateway", 11},                      // 502
    [403] = {"Service Unavailable", 19},              // 503
    [404] = {"Gateway Timeout", 15},                  // 504
    [405] = {"HTTP Version Not Supported", 26},       // 505
    [406] = {"Variant Also Negotiates", 23},          // 506
    [407] = {"Insufficient Storage", 20},             // 507
    [408] = {"Loop Detected", 13},                    // 508
    [410] = {"Not Extended", 12},                     // 510
    [411] = {"Network Authentication Required", 31},  // 511
};

#define INLINE_FUNC __attribute__((always_inline)) static inline

// Direct lookup using status code as index
INLINE_FUNC const status_info_t* get_http_status(http_status code) {
    if (code < STATUS_MIN || code > STATUS_MAX) {
        return NULL;
    }
    const status_info_t* info = &status_info[code - STATUS_MIN];
    return info->text ? info : NULL;  // Check if slot is populated
}

INLINE_FUNC bool http_status_valid(http_status code) {
    return (code >= STATUS_MIN || code <= STATUS_MAX);
}

#ifdef __cplusplus
}
#endif

#endif /* STATUS_CODE_H */
