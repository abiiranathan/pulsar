#ifndef CONTENT_TYPES_H
#define CONTENT_TYPES_H

#include <stddef.h>

// Text types
#define HTML_TYPE       "text/html"
#define PLAINTEXT_TYPE  "text/plain"
#define CSV_TYPE        "text/csv"
#define CSS_TYPE        "text/css"
#define XML_TYPE        "application/xml"
#define JAVASCRIPT_TYPE "application/javascript"
#define MARKDOWN_TYPE   "text/markdown"
#define RTF_TYPE        "application/rtf"

// JSON and related
#define JSON_TYPE        "application/json"
#define JSONLD_TYPE      "application/ld+json"
#define WEBMANIFEST_TYPE "application/manifest+json"

// Document types
#define PDF_TYPE     "application/pdf"
#define MSWORD_TYPE  "application/msword"
#define MSEXCEL_TYPE "application/vnd.ms-excel"
#define MSPPT_TYPE   "application/vnd.ms-powerpoint"
#define DOCX_TYPE    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
#define XLSX_TYPE    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
#define PPTX_TYPE    "application/vnd.openxmlformats-officedocument.presentationml.presentation"
#define ODT_TYPE     "application/vnd.oasis.opendocument.text"
#define ODS_TYPE     "application/vnd.oasis.opendocument.spreadsheet"

// Image types
#define PNG_TYPE  "image/png"
#define JPEG_TYPE "image/jpeg"
#define GIF_TYPE  "image/gif"
#define BMP_TYPE  "image/bmp"
#define WEBP_TYPE "image/webp"
#define TIFF_TYPE "image/tiff"
#define SVG_TYPE  "image/svg+xml"
#define ICO_TYPE  "image/vnd.microsoft.icon"

// Font types
#define TTF_TYPE   "font/ttf"
#define OTF_TYPE   "font/otf"
#define WOFF_TYPE  "font/woff"
#define WOFF2_TYPE "font/woff2"

// Audio types
#define MP3_TYPE   "audio/mpeg"
#define OGG_TYPE   "audio/ogg"
#define WAV_TYPE   "audio/wav"
#define AAC_TYPE   "audio/aac"
#define FLAC_TYPE  "audio/flac"
#define WEBMA_TYPE "audio/webm"

// Video types
#define MP4_TYPE  "video/mp4"
#define WEBM_TYPE "video/webm"
#define OGV_TYPE  "video/ogg"
#define AVI_TYPE  "video/x-msvideo"
#define MOV_TYPE  "video/quicktime"
#define MPEG_TYPE "video/mpeg"

// Archive types
#define ZIP_TYPE    "application/zip"
#define TAR_TYPE    "application/x-tar"
#define GZIP_TYPE   "application/gzip"
#define BZIP2_TYPE  "application/x-bzip2"
#define SEVENZ_TYPE "application/x-7z-compressed"
#define RAR_TYPE    "application/vnd.rar"

// Binary stream
#define OCTET_STREAM_TYPE "application/octet-stream"

// Form data
#define FORM_URLENCODED_TYPE "application/x-www-form-urlencoded"
#define FORM_MULTIPART_TYPE  "multipart/form-data"

#endif /* CONTENT_TYPES_H */
