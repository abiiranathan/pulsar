#ifndef CONTENT_TYPES_H
#define CONTENT_TYPES_H

#include <stddef.h>

// Central X-macro list of MIME types
#define CONTENT_TYPES_X                                                                            \
    X(HTML, "text/html")                                                                           \
    X(PLAINTEXT, "text/plain")                                                                     \
    X(CSV, "text/csv")                                                                             \
    X(CSS, "text/css")                                                                             \
    X(XML, "application/xml")                                                                      \
    X(JAVASCRIPT, "application/javascript")                                                        \
    X(MARKDOWN, "text/markdown")                                                                   \
    X(RTF, "application/rtf")                                                                      \
                                                                                                   \
    X(JSON, "application/json")                                                                    \
    X(JSONLD, "application/ld+json")                                                               \
    X(WEBMANIFEST, "application/manifest+json")                                                    \
                                                                                                   \
    X(PDF, "application/pdf")                                                                      \
    X(MSWORD, "application/msword")                                                                \
    X(MSEXCEL, "application/vnd.ms-excel")                                                         \
    X(MSPPT, "application/vnd.ms-powerpoint")                                                      \
    X(DOCX, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")             \
    X(XLSX, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")                   \
    X(PPTX, "application/vnd.openxmlformats-officedocument.presentationml.presentation")           \
    X(ODT, "application/vnd.oasis.opendocument.text")                                              \
    X(ODS, "application/vnd.oasis.opendocument.spreadsheet")                                       \
                                                                                                   \
    X(PNG, "image/png")                                                                            \
    X(JPEG, "image/jpeg")                                                                          \
    X(GIF, "image/gif")                                                                            \
    X(BMP, "image/bmp")                                                                            \
    X(WEBP, "image/webp")                                                                          \
    X(TIFF, "image/tiff")                                                                          \
    X(SVG, "image/svg+xml")                                                                        \
    X(ICO, "image/vnd.microsoft.icon")                                                             \
                                                                                                   \
    X(TTF, "font/ttf")                                                                             \
    X(OTF, "font/otf")                                                                             \
    X(WOFF, "font/woff")                                                                           \
    X(WOFF2, "font/woff2")                                                                         \
                                                                                                   \
    X(MP3, "audio/mpeg")                                                                           \
    X(OGG, "audio/ogg")                                                                            \
    X(WAV, "audio/wav")                                                                            \
    X(AAC, "audio/aac")                                                                            \
    X(FLAC, "audio/flac")                                                                          \
    X(WEBMA, "audio/webm")                                                                         \
                                                                                                   \
    X(MP4, "video/mp4")                                                                            \
    X(WEBM, "video/webm")                                                                          \
    X(OGV, "video/ogg")                                                                            \
    X(AVI, "video/x-msvideo")                                                                      \
    X(MOV, "video/quicktime")                                                                      \
    X(MPEG, "video/mpeg")                                                                          \
                                                                                                   \
    X(ZIP, "application/zip")                                                                      \
    X(TAR, "application/x-tar")                                                                    \
    X(GZIP, "application/gzip")                                                                    \
    X(BZIP2, "application/x-bzip2")                                                                \
    X(SEVENZ, "application/x-7z-compressed")                                                       \
    X(RAR, "application/vnd.rar")                                                                  \
                                                                                                   \
    X(OCTET_STREAM, "application/octet-stream")                                                    \
                                                                                                   \
    X(FORM_URLENCODED, "application/x-www-form-urlencoded")                                        \
    X(FORM_MULTIPART, "multipart/form-data")

// Generated 2 constants per content-type.
// e.g HTML_TYPE & HTML_TYPE_SIZE.
// Expand X-macro into static constants
#define X(NAME, VALUE)                                                                             \
    static const char NAME##_TYPE[]      = VALUE;                                                  \
    static const size_t NAME##_TYPE_SIZE = sizeof(VALUE) - 1;
CONTENT_TYPES_X
#undef X

#endif /* CONTENT_TYPES_H */
