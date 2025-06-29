#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
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

// http_status_text returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go

// http_status_text returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go

// Array of status text strings
static const char* status_texts[] = {
    [StatusContinue]                      = "Continue",
    [StatusSwitchingProtocols]            = "Switching Protocols",
    [StatusProcessing]                    = "Processing",
    [StatusEarlyHints]                    = "Early Hints",
    [StatusOK]                            = "OK",
    [StatusCreated]                       = "Created",
    [StatusAccepted]                      = "Accepted",
    [StatusNonAuthoritativeInfo]          = "Non-Authoritative Information",
    [StatusNoContent]                     = "No Content",
    [StatusResetContent]                  = "Reset Content",
    [StatusPartialContent]                = "Partial Content",
    [StatusMultiStatus]                   = "Multi-Status",
    [StatusAlreadyReported]               = "Already Reported",
    [StatusIMUsed]                        = "IM Used",
    [StatusMultipleChoices]               = "Multiple Choices",
    [StatusMovedPermanently]              = "Moved Permanently",
    [StatusFound]                         = "Found",
    [StatusSeeOther]                      = "See Other",
    [StatusNotModified]                   = "Not Modified",
    [StatusUseProxy]                      = "Use Proxy",
    [StatusTemporaryRedirect]             = "Temporary Redirect",
    [StatusPermanentRedirect]             = "Permanent Redirect",
    [StatusBadRequest]                    = "Bad Request",
    [StatusUnauthorized]                  = "Unauthorized",
    [StatusPaymentRequired]               = "Payment Required",
    [StatusForbidden]                     = "Forbidden",
    [StatusNotFound]                      = "Not Found",
    [StatusMethodNotAllowed]              = "Method Not Allowed",
    [StatusNotAcceptable]                 = "Not Acceptable",
    [StatusProxyAuthRequired]             = "Proxy Authentication Required",
    [StatusRequestTimeout]                = "Request Timeout",
    [StatusConflict]                      = "Conflict",
    [StatusGone]                          = "Gone",
    [StatusLengthRequired]                = "Length Required",
    [StatusPreconditionFailed]            = "Precondition Failed",
    [StatusRequestEntityTooLarge]         = "Request Entity Too Large",
    [StatusRequestURITooLong]             = "Request URI Too Long",
    [StatusUnsupportedMediaType]          = "Unsupported Media Type",
    [StatusRequestedRangeNotSatisfiable]  = "Requested Range Not Satisfiable",
    [StatusExpectationFailed]             = "Expectation Failed",
    [StatusTeapot]                        = "I'm a teapot",
    [StatusMisdirectedRequest]            = "Misdirected Request",
    [StatusUnprocessableEntity]           = "Unprocessable Entity",
    [StatusLocked]                        = "Locked",
    [StatusFailedDependency]              = "Failed Dependency",
    [StatusTooEarly]                      = "Too Early",
    [StatusUpgradeRequired]               = "Upgrade Required",
    [StatusPreconditionRequired]          = "Precondition Required",
    [StatusTooManyRequests]               = "Too Many Requests",
    [StatusRequestHeaderFieldsTooLarge]   = "Request Header Fields Too Large",
    [StatusUnavailableForLegalReasons]    = "Unavailable For Legal Reasons",
    [StatusInternalServerError]           = "Internal Server Error",
    [StatusNotImplemented]                = "Not Implemented",
    [StatusBadGateway]                    = "Bad Gateway",
    [StatusServiceUnavailable]            = "Service Unavailable",
    [StatusGatewayTimeout]                = "Gateway Timeout",
    [StatusHTTPVersionNotSupported]       = "HTTP Version Not Supported",
    [StatusVariantAlsoNegotiates]         = "Variant Also Negotiates",
    [StatusInsufficientStorage]           = "Insufficient Storage",
    [StatusLoopDetected]                  = "Loop Detected",
    [StatusNotExtended]                   = "Not Extended",
    [StatusNetworkAuthenticationRequired] = "Network Authentication Required",
};

static inline const char* http_status_text(http_status code) {
    if (code >= StatusContinue && code <= StatusNetworkAuthenticationRequired) {
        return status_texts[code];
    }
    return "";  // Return empty string for unknown codes
}

static inline bool http_status_valid(http_status code) {
    return code >= StatusContinue && code <= StatusNetworkAuthenticationRequired;
}

#ifdef __cplusplus
}
#endif

#endif /* STATUS_CODE_H */
