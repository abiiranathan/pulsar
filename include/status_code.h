#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum : uint32_t {
    StatusContinue                      = 100,
    StatusSwitchingProtocols            = 101,
    StatusProcessing                    = 102,
    StatusEarlyHints                    = 103,
    StatusOK                            = 200,
    StatusCreated                       = 201,
    StatusAccepted                      = 202,
    StatusNonAuthoritativeInfo          = 203,
    StatusNoContent                     = 204,
    StatusResetContent                  = 205,
    StatusPartialContent                = 206,
    StatusMultiStatus                   = 207,
    StatusAlreadyReported               = 208,
    StatusIMUsed                        = 226,
    StatusMultipleChoices               = 300,
    StatusMovedPermanently              = 301,
    StatusFound                         = 302,
    StatusSeeOther                      = 303,
    StatusNotModified                   = 304,
    StatusUseProxy                      = 305,
    StatusUnused                        = 306,
    StatusTemporaryRedirect             = 307,
    StatusPermanentRedirect             = 308,
    StatusBadRequest                    = 400,
    StatusUnauthorized                  = 401,
    StatusPaymentRequired               = 402,
    StatusForbidden                     = 403,
    StatusNotFound                      = 404,
    StatusMethodNotAllowed              = 405,
    StatusNotAcceptable                 = 406,
    StatusProxyAuthRequired             = 407,
    StatusRequestTimeout                = 408,
    StatusConflict                      = 409,
    StatusGone                          = 410,
    StatusLengthRequired                = 411,
    StatusPreconditionFailed            = 412,
    StatusRequestEntityTooLarge         = 413,
    StatusRequestURITooLong             = 414,
    StatusUnsupportedMediaType          = 415,
    StatusRequestedRangeNotSatisfiable  = 416,
    StatusExpectationFailed             = 417,
    StatusTeapot                        = 418,
    StatusMisdirectedRequest            = 421,
    StatusUnprocessableEntity           = 422,
    StatusLocked                        = 423,
    StatusFailedDependency              = 424,
    StatusTooEarly                      = 425,
    StatusUpgradeRequired               = 426,
    StatusPreconditionRequired          = 428,
    StatusTooManyRequests               = 429,
    StatusRequestHeaderFieldsTooLarge   = 431,
    StatusUnavailableForLegalReasons    = 451,
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
static constexpr uint32_t STATUS_MIN        = StatusContinue;
static constexpr uint32_t STATUS_MAX        = StatusNetworkAuthenticationRequired;
static constexpr uint32_t STATUS_TABLE_SIZE = (STATUS_MAX - STATUS_MIN + 1);

static status_info_t status_info[STATUS_TABLE_SIZE];
static pthread_once_t status_tables_once = PTHREAD_ONCE_INIT;

/** Initializes the HTTP status code lookup table. Called automatically by
 * get_http_status(). */
static inline void init_status_info(void) {

    // Initialize all entries to zero
    for (size_t i = 0; i < STATUS_TABLE_SIZE; i++) {
        status_info[i].text   = NULL;
        status_info[i].length = 0;
    }

    // 1xx Informational
    status_info[0].text   = "Continue";
    status_info[0].length = 8;  // 100
    status_info[1].text   = "Switching Protocols";
    status_info[1].length = 19;  // 101
    status_info[2].text   = "Processing";
    status_info[2].length = 10;  // 102
    status_info[3].text   = "Early Hints";
    status_info[3].length = 11;  // 103

    // 2xx Success
    status_info[100].text   = "OK";
    status_info[100].length = 2;  // 200
    status_info[101].text   = "Created";
    status_info[101].length = 7;  // 201
    status_info[102].text   = "Accepted";
    status_info[102].length = 8;  // 202
    status_info[103].text   = "Non-Authoritative Information";
    status_info[103].length = 29;  // 203
    status_info[104].text   = "No Content";
    status_info[104].length = 10;  // 204
    status_info[105].text   = "Reset Content";
    status_info[105].length = 13;  // 205
    status_info[106].text   = "Partial Content";
    status_info[106].length = 15;  // 206
    status_info[107].text   = "Multi-Status";
    status_info[107].length = 12;  // 207
    status_info[108].text   = "Already Reported";
    status_info[108].length = 16;  // 208
    status_info[126].text   = "IM Used";
    status_info[126].length = 7;  // 226

    // 3xx Redirection
    status_info[200].text   = "Multiple Choices";
    status_info[200].length = 16;  // 300
    status_info[201].text   = "Moved Permanently";
    status_info[201].length = 17;  // 301
    status_info[202].text   = "Found";
    status_info[202].length = 5;  // 302
    status_info[203].text   = "See Other";
    status_info[203].length = 9;  // 303
    status_info[204].text   = "Not Modified";
    status_info[204].length = 12;  // 304
    status_info[205].text   = "Use Proxy";
    status_info[205].length = 9;  // 305
    status_info[206].text   = "Unused";
    status_info[206].length = 6;  // 306
    status_info[207].text   = "Temporary Redirect";
    status_info[207].length = 18;  // 307
    status_info[208].text   = "Permanent Redirect";
    status_info[208].length = 18;  // 308

    // 4xx Client Errors
    status_info[300].text   = "Bad Request";
    status_info[300].length = 11;  // 400
    status_info[301].text   = "Unauthorized";
    status_info[301].length = 12;  // 401
    status_info[302].text   = "Payment Required";
    status_info[302].length = 16;  // 402
    status_info[303].text   = "Forbidden";
    status_info[303].length = 9;  // 403
    status_info[304].text   = "Not Found";
    status_info[304].length = 9;  // 404
    status_info[305].text   = "Method Not Allowed";
    status_info[305].length = 18;  // 405
    status_info[306].text   = "Not Acceptable";
    status_info[306].length = 14;  // 406
    status_info[307].text   = "Proxy Authentication Required";
    status_info[307].length = 29;  // 407
    status_info[308].text   = "Request Timeout";
    status_info[308].length = 15;  // 408
    status_info[309].text   = "Conflict";
    status_info[309].length = 8;  // 409
    status_info[310].text   = "Gone";
    status_info[310].length = 4;  // 410
    status_info[311].text   = "Length Required";
    status_info[311].length = 15;  // 411
    status_info[312].text   = "Precondition Failed";
    status_info[312].length = 19;  // 412
    status_info[313].text   = "Request Entity Too Large";
    status_info[313].length = 24;  // 413
    status_info[314].text   = "Request URI Too Long";
    status_info[314].length = 20;  // 414
    status_info[315].text   = "Unsupported Media Type";
    status_info[315].length = 22;  // 415
    status_info[316].text   = "Requested Range Not Satisfiable";
    status_info[316].length = 31;  // 416
    status_info[317].text   = "Expectation Failed";
    status_info[317].length = 18;  // 417
    status_info[318].text   = "I'm a teapot";
    status_info[318].length = 12;  // 418
    status_info[321].text   = "Misdirected Request";
    status_info[321].length = 19;  // 421
    status_info[322].text   = "Unprocessable Entity";
    status_info[322].length = 20;  // 422
    status_info[323].text   = "Locked";
    status_info[323].length = 6;  // 423
    status_info[324].text   = "Failed Dependency";
    status_info[324].length = 17;  // 424
    status_info[325].text   = "Too Early";
    status_info[325].length = 9;  // 425
    status_info[326].text   = "Upgrade Required";
    status_info[326].length = 16;  // 426
    status_info[328].text   = "Precondition Required";
    status_info[328].length = 21;  // 428
    status_info[329].text   = "Too Many Requests";
    status_info[329].length = 17;  // 429
    status_info[331].text   = "Request Header Fields Too Large";
    status_info[331].length = 31;  // 431
    status_info[351].text   = "Unavailable For Legal Reasons";
    status_info[351].length = 29;  // 451

    // 5xx Server Errors
    status_info[400].text   = "Internal Server Error";
    status_info[400].length = 21;  // 500
    status_info[401].text   = "Not Implemented";
    status_info[401].length = 15;  // 501
    status_info[402].text   = "Bad Gateway";
    status_info[402].length = 11;  // 502
    status_info[403].text   = "Service Unavailable";
    status_info[403].length = 19;  // 503
    status_info[404].text   = "Gateway Timeout";
    status_info[404].length = 15;  // 504
    status_info[405].text   = "HTTP Version Not Supported";
    status_info[405].length = 26;  // 505
    status_info[406].text   = "Variant Also Negotiates";
    status_info[406].length = 23;  // 506
    status_info[407].text   = "Insufficient Storage";
    status_info[407].length = 20;  // 507
    status_info[408].text   = "Loop Detected";
    status_info[408].length = 13;  // 508
    status_info[410].text   = "Not Extended";
    status_info[410].length = 12;  // 510
    status_info[411].text   = "Network Authentication Required";
    status_info[411].length = 31;  // 511
}

/**
 * Gets the status text for a given HTTP status code.
 * @param code The HTTP status code.
 * @return Pointer to status_info_t containing text and length, or default to
 * 200 OK if invalid.
 */
INLINE const status_info_t* get_http_status(http_status code) {
    pthread_once(&status_tables_once, init_status_info);

    if (code < STATUS_MIN || code > STATUS_MAX) {
        return NULL;
    }
    const status_info_t* info = &status_info[code - STATUS_MIN];
    return info->text ? info : &status_info[100];  // default to 200 OK if invalid.
}

/**
 * Checks if an HTTP status code is within the valid range.
 * @param code The HTTP status code to validate.
 * @return true if code is within valid range, false otherwise.
 */
INLINE bool http_status_valid(http_status code) {
    return (code >= STATUS_MIN && code <= STATUS_MAX);
}

#ifdef __cplusplus
}
#endif

#endif /* STATUS_CODE_H */
