#ifndef CONTENT_TYPES_H
#define CONTENT_TYPES_H

#include <stddef.h>

// Content-Type header
#define CONTENT_TYPE_HEADER "Content-Type"

// Text types
#define CONTENT_TYPE_HTML       "text/html"
#define CONTENT_TYPE_PLAIN      "text/plain"
#define CONTENT_TYPE_CSV        "text/csv"
#define CONTENT_TYPE_CSS        "text/css"
#define CONTENT_TYPE_XML        "application/xml"
#define CONTENT_TYPE_JAVASCRIPT "application/javascript"
#define CONTENT_TYPE_MARKDOWN   "text/markdown"
#define CONTENT_TYPE_RTF        "application/rtf"

// JSON and related
#define CONTENT_TYPE_JSON        "application/json"
#define CONTENT_TYPE_JSONLD      "application/ld+json"
#define CONTENT_TYPE_WEBMANIFEST "application/manifest+json"

// Document types
#define CONTENT_TYPE_PDF     "application/pdf"
#define CONTENT_TYPE_MSWORD  "application/msword"
#define CONTENT_TYPE_MSEXCEL "application/vnd.ms-excel"
#define CONTENT_TYPE_MSPPT   "application/vnd.ms-powerpoint"
#define CONTENT_TYPE_DOCX    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#define CONTENT_TYPE_XLSX    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#define CONTENT_TYPE_PPTX                                                                          \
    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
#define CONTENT_TYPE_ODT "application/vnd.oasis.opendocument.text"
#define CONTENT_TYPE_ODS "application/vnd.oasis.opendocument.spreadsheet"

// Image types
#define CONTENT_TYPE_PNG  "image/png"
#define CONTENT_TYPE_JPEG "image/jpeg"
#define CONTENT_TYPE_GIF  "image/gif"
#define CONTENT_TYPE_BMP  "image/bmp"
#define CONTENT_TYPE_WEBP "image/webp"
#define CONTENT_TYPE_TIFF "image/tiff"
#define CONTENT_TYPE_SVG  "image/svg+xml"
#define CONTENT_TYPE_ICO  "image/vnd.microsoft.icon"

// Font types
#define CONTENT_TYPE_TTF   "font/ttf"
#define CONTENT_TYPE_OTF   "font/otf"
#define CONTENT_TYPE_WOFF  "font/woff"
#define CONTENT_TYPE_WOFF2 "font/woff2"

// Audio types
#define CONTENT_TYPE_MP3   "audio/mpeg"
#define CONTENT_TYPE_OGG   "audio/ogg"
#define CONTENT_TYPE_WAV   "audio/wav"
#define CONTENT_TYPE_AAC   "audio/aac"
#define CONTENT_TYPE_FLAC  "audio/flac"
#define CONTENT_TYPE_WEBMA "audio/webm"

// Video types
#define CONTENT_TYPE_MP4  "video/mp4"
#define CONTENT_TYPE_WEBM "video/webm"
#define CONTENT_TYPE_OGV  "video/ogg"
#define CONTENT_TYPE_AVI  "video/x-msvideo"
#define CONTENT_TYPE_MOV  "video/quicktime"
#define CONTENT_TYPE_MPEG "video/mpeg"

// Archive types
#define CONTENT_TYPE_ZIP   "application/zip"
#define CONTENT_TYPE_TAR   "application/x-tar"
#define CONTENT_TYPE_GZIP  "application/gzip"
#define CONTENT_TYPE_BZIP2 "application/x-bzip2"
#define CONTENT_TYPE_7Z    "application/x-7z-compressed"
#define CONTENT_TYPE_RAR   "application/vnd.rar"

// Binary stream
#define CONTENT_TYPE_OCTET "application/octet-stream"

// Form data
#define CONTENT_TYPE_FORM_URLENCODED "application/x-www-form-urlencoded"
#define CONTENT_TYPE_FORM_MULTIPART  "multipart/form-data"

#endif /* CONTENT_TYPES_H */
