#ifndef CONTENT_TYPES_H
#define CONTENT_TYPES_H

#include <stddef.h>

// Content-Type header
#define CT_HEADER "Content-Type"

// Text types
#define CT_HTML "text/html"
#define CT_PLAIN "text/plain"
#define CT_CSV "text/csv"
#define CT_CSS "text/css"
#define CT_XML "application/xml"
#define CT_JAVASCRIPT "application/javascript"
#define CT_MARKDOWN "text/markdown"
#define CT_RTF "application/rtf"

// JSON and related
#define CT_JSON "application/json"
#define CT_JSONLD "application/ld+json"
#define CT_WEBMANIFEST "application/manifest+json"

// Document types
#define CT_PDF "application/pdf"
#define CT_MSWORD "application/msword"
#define CT_MSEXCEL "application/vnd.ms-excel"
#define CT_MSPPT "application/vnd.ms-powerpoint"
#define CT_DOCX "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#define CT_XLSX "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#define CT_PPTX "application/vnd.openxmlformats-officedocument.presentationml.presentation"
#define CT_ODT "application/vnd.oasis.opendocument.text"
#define CT_ODS "application/vnd.oasis.opendocument.spreadsheet"

// Image types
#define CT_PNG "image/png"
#define CT_JPEG "image/jpeg"
#define CT_GIF "image/gif"
#define CT_BMP "image/bmp"
#define CT_WEBP "image/webp"
#define CT_TIFF "image/tiff"
#define CT_SVG "image/svg+xml"
#define CT_ICO "image/vnd.microsoft.icon"

// Font types
#define CT_TTF "font/ttf"
#define CT_OTF "font/otf"
#define CT_WOFF "font/woff"
#define CT_WOFF2 "font/woff2"

// Audio types
#define CT_MP3 "audio/mpeg"
#define CT_OGG "audio/ogg"
#define CT_WAV "audio/wav"
#define CT_AAC "audio/aac"
#define CT_FLAC "audio/flac"
#define CT_WEBMA "audio/webm"

// Video types
#define CT_MP4 "video/mp4"
#define CT_WEBM "video/webm"
#define CT_OGV "video/ogg"
#define CT_AVI "video/x-msvideo"
#define CT_MOV "video/quicktime"
#define CT_MPEG "video/mpeg"

// Archive types
#define CT_ZIP "application/zip"
#define CT_TAR "application/x-tar"
#define CT_GZIP "application/gzip"
#define CT_BZIP2 "application/x-bzip2"
#define CT_7Z "application/x-7z-compressed"
#define CT_RAR "application/vnd.rar"

// Binary stream
#define CT_OCTET "application/octet-stream"

// Form data
#define CT_FORM_URLENCODED "application/x-www-form-urlencoded"
#define CT_FORM_MULTIPART "multipart/form-data"

#endif /* CONTENT_TYPES_H */
