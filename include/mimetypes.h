#ifndef MIMETYPE_H
#define MIMETYPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <solidc/str_slice.h>
#include <stddef.h>
#include <string.h>
#include "macros.h"

// ============= Predefined mime types ====================
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

// =============== Mime mapping data structure=======================

typedef struct MimeEntry {
    const char* ext;         // Extension in lowercase.
    StrSlice mimetype;       // Real mime type.
    struct MimeEntry* next;  // For chaining in case of collisions
} MimeEntry;

static MimeEntry mime_entries[] = {
    // Text mime types
    {.ext = "html", .mimetype = SS_LIT("text/html")},
    {.ext = "htm", .mimetype = SS_LIT("text/html")},
    {.ext = "xhtml", .mimetype = SS_LIT("application/xhtml+xml")},
    {.ext = "php", .mimetype = SS_LIT("application/x-httpd-php")},
    {.ext = "xml", .mimetype = SS_LIT("application/xml")},
    {.ext = "css", .mimetype = SS_LIT("text/css")},
    {.ext = "js", .mimetype = SS_LIT("application/javascript")},
    {.ext = "txt", .mimetype = SS_LIT("text/plain")},
    {.ext = "json", .mimetype = SS_LIT("application/json")},
    {.ext = "csv", .mimetype = SS_LIT("text/csv")},
    {.ext = "md", .mimetype = SS_LIT("text/markdown")},
    {.ext = "webmanifest", .mimetype = SS_LIT("application/manifest+json")},

    // Images
    {.ext = "jpg", .mimetype = SS_LIT("image/jpeg")},
    {.ext = "jpeg", .mimetype = SS_LIT("image/jpeg")},
    {.ext = "png", .mimetype = SS_LIT("image/png")},
    {.ext = "gif", .mimetype = SS_LIT("image/gif")},
    {.ext = "ico", .mimetype = SS_LIT("image/x-icon")},
    {.ext = "svg", .mimetype = SS_LIT("image/svg+xml")},
    {.ext = "bmp", .mimetype = SS_LIT("image/bmp")},
    {.ext = "tiff", .mimetype = SS_LIT("image/tiff")},
    {.ext = "webp", .mimetype = SS_LIT("image/webp")},

    // Documents
    {.ext = "pdf", .mimetype = SS_LIT("application/pdf")},
    {.ext = "doc", .mimetype = SS_LIT("application/msword")},
    {.ext = "docx", .mimetype = SS_LIT("application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
    {
        .ext = "pptx",
        .mimetype = SS_LIT("application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    },
    {.ext = "xls", .mimetype = SS_LIT("application/vnd.ms-excel")},
    {
        .ext = "xlsx",
        .mimetype = SS_LIT("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    },
    {.ext = "odt", .mimetype = SS_LIT("application/vnd.oasis.opendocument.text")},
    {.ext = "ods", .mimetype = SS_LIT("application/vnd.oasis.opendocument.spreadsheet")},
    {.ext = "odp", .mimetype = SS_LIT("application/vnd.oasis.opendocument.presentation")},
    {.ext = "latex", .mimetype = SS_LIT("application/x-latex")},

    // Programming language source files
    {.ext = "c", .mimetype = SS_LIT("text/x-c")},
    {.ext = "cc", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "cpp", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "c++", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "rs", .mimetype = SS_LIT("text/x-rust")},
    {.ext = "h", .mimetype = SS_LIT("text/x-c")},
    {.ext = "hh", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "hpp", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "h++", .mimetype = SS_LIT("text/x-c++")},
    {.ext = "cs", .mimetype = SS_LIT("text/x-csharp")},
    {.ext = "java", .mimetype = SS_LIT("text/x-java-source")},
    {.ext = "py", .mimetype = SS_LIT("text/x-python")},
    {.ext = "sh", .mimetype = SS_LIT("application/x-shellscript")},
    {.ext = "bat", .mimetype = SS_LIT("application/x-bat")},
    {.ext = "pl", .mimetype = SS_LIT("application/x-perl")},
    {.ext = "rb", .mimetype = SS_LIT("application/x-ruby")},
    {.ext = "php", .mimetype = SS_LIT("application/x-php")},
    {.ext = "go", .mimetype = SS_LIT("text/x-go")},
    {.ext = "swift", .mimetype = SS_LIT("text/x-swift")},
    {.ext = "lua", .mimetype = SS_LIT("text/x-lua")},
    {.ext = "r", .mimetype = SS_LIT("text/x-r")},
    {.ext = "sql", .mimetype = SS_LIT("application/sql")},
    {.ext = "asm", .mimetype = SS_LIT("text/x-asm")},
    {.ext = "s", .mimetype = SS_LIT("text/x-asm")},
    {.ext = "clj", .mimetype = SS_LIT("text/x-clojure")},
    {.ext = "lisp", .mimetype = SS_LIT("text/x-lisp")},
    {.ext = "scm", .mimetype = SS_LIT("text/x-scheme")},
    {.ext = "ss", .mimetype = SS_LIT("text/x-scheme")},
    {.ext = "rkt", .mimetype = SS_LIT("text/x-scheme")},
    {.ext = "jl", .mimetype = SS_LIT("text/x-julia")},
    {.ext = "kt", .mimetype = SS_LIT("text/x-kotlin")},
    {.ext = "dart", .mimetype = SS_LIT("text/x-dart")},
    {.ext = "scala", .mimetype = SS_LIT("text/x-scala")},
    {.ext = "groovy", .mimetype = SS_LIT("text/x-groovy")},
    {.ext = "ts", .mimetype = SS_LIT("text/typescript")},
    {.ext = "tsx", .mimetype = SS_LIT("text/typescript")},
    {.ext = "jsx", .mimetype = SS_LIT("text/jsx")},
    {.ext = "elm", .mimetype = SS_LIT("text/x-elm")},
    {.ext = "erl", .mimetype = SS_LIT("text/x-erlang")},
    {.ext = "hrl", .mimetype = SS_LIT("text/x-erlang")},
    {.ext = "ex", .mimetype = SS_LIT("text/x-elixir")},
    {.ext = "exs", .mimetype = SS_LIT("text/x-elixir")},
    {.ext = "cl", .mimetype = SS_LIT("text/x-common-lisp")},
    {.ext = "lsp", .mimetype = SS_LIT("text/x-common-lisp")},
    {.ext = "f", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "f77", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "f90", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "for", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "nim", .mimetype = SS_LIT("text/x-nim")},
    {.ext = "v", .mimetype = SS_LIT("text/x-verilog")},
    {.ext = "sv", .mimetype = SS_LIT("text/x-systemverilog")},
    {.ext = "vhd", .mimetype = SS_LIT("text/x-vhdl")},
    {.ext = "dic", .mimetype = SS_LIT("text/x-c")},
    {.ext = "h", .mimetype = SS_LIT("text/x-c")},
    {.ext = "hh", .mimetype = SS_LIT("text/x-c")},
    {.ext = "f", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "f77", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "f90", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "for", .mimetype = SS_LIT("text/x-fortran")},
    {.ext = "java", .mimetype = SS_LIT("text/x-java-source")},
    {.ext = "p", .mimetype = SS_LIT("text/x-pascal")},
    {.ext = "pas", .mimetype = SS_LIT("text/x-pascal")},
    {.ext = "pp", .mimetype = SS_LIT("text/x-pascal")},
    {.ext = "inc", .mimetype = SS_LIT("text/x-pascal")},
    {.ext = "py", .mimetype = SS_LIT("text/x-python")},

    // Other
    {.ext = "etx", .mimetype = SS_LIT("text/x-setext")},
    {.ext = "uu", .mimetype = SS_LIT("text/x-uuencode")},
    {.ext = "vcs", .mimetype = SS_LIT("text/x-vcalendar")},
    {.ext = "vcf", .mimetype = SS_LIT("text/x-vcard")},

    // Video
    {.ext = "mp4", .mimetype = SS_LIT("video/mp4")},
    {.ext = "avi", .mimetype = SS_LIT("video/avi")},
    {.ext = "mkv", .mimetype = SS_LIT("video/x-matroska")},
    {.ext = "mov", .mimetype = SS_LIT("video/quicktime")},
    {.ext = "wmv", .mimetype = SS_LIT("video/x-ms-wmv")},
    {.ext = "flv", .mimetype = SS_LIT("video/x-flv")},
    {.ext = "mpeg", .mimetype = SS_LIT("video/mpeg")},
    {.ext = "webm", .mimetype = SS_LIT("video/webm")},

    // Audio
    {.ext = "mp3", .mimetype = SS_LIT("audio/mpeg")},
    {.ext = "wav", .mimetype = SS_LIT("audio/wav")},
    {.ext = "flac", .mimetype = SS_LIT("audio/flac")},
    {.ext = "aac", .mimetype = SS_LIT("audio/aac")},
    {.ext = "ogg", .mimetype = SS_LIT("audio/ogg")},
    {.ext = "wma", .mimetype = SS_LIT("audio/x-ms-wma")},
    {.ext = "m4a", .mimetype = SS_LIT("audio/m4a")},
    {.ext = "mid", .mimetype = SS_LIT("audio/midi")},

    // Archives
    {.ext = "zip", .mimetype = SS_LIT("application/zip")},
    {.ext = "rar", .mimetype = SS_LIT("application/x-rar-compressed")},
    {.ext = "tar", .mimetype = SS_LIT("application/x-tar")},
    {.ext = "7z", .mimetype = SS_LIT("application/x-7z-compressed")},
    {.ext = "gz", .mimetype = SS_LIT("application/gzip")},
    {.ext = "bz2", .mimetype = SS_LIT("application/x-bzip2")},
    {.ext = "xz", .mimetype = SS_LIT("application/x-xz")},

    // Spreadsheets
    {.ext = "ods", .mimetype = SS_LIT("application/vnd.oasis.opendocument.spreadsheet")},
    {.ext = "csv", .mimetype = SS_LIT("text/csv")},
    {.ext = "tsv", .mimetype = SS_LIT("text/tab-separated-values")},

    // Applications
    {.ext = "exe", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "apk", .mimetype = SS_LIT("application/vnd.android.package-archive")},
    {.ext = "dmg", .mimetype = SS_LIT("application/x-apple-diskimage")},

    // Fonts
    {.ext = "ttf", .mimetype = SS_LIT("font/ttf")},
    {.ext = "otf", .mimetype = SS_LIT("font/otf")},
    {.ext = "woff", .mimetype = SS_LIT("font/woff")},
    {.ext = "woff2", .mimetype = SS_LIT("font/woff2")},

    // 3D Models
    {.ext = "obj", .mimetype = SS_LIT("model/obj")},
    {.ext = "stl", .mimetype = SS_LIT("model/stl")},
    {.ext = "gltf", .mimetype = SS_LIT("model/gltf+json")},

    // GIS
    {.ext = "kml", .mimetype = SS_LIT("application/vnd.google-earth.kml+xml")},
    {.ext = "kmz", .mimetype = SS_LIT("application/vnd.google-earth.kmz")},

    // Other
    {.ext = "rss", .mimetype = SS_LIT("application/rss+xml")},
    {.ext = "yaml", .mimetype = SS_LIT("application/x-yaml")},
    {.ext = "ini", .mimetype = SS_LIT("text/plain")},
    {.ext = "cfg", .mimetype = SS_LIT("text/plain")},
    {.ext = "log", .mimetype = SS_LIT("text/plain")},

    // Database Formats
    {.ext = "sqlite", .mimetype = SS_LIT("application/x-sqlite3")},
    {.ext = "sql", .mimetype = SS_LIT("application/sql")},

    // Ebooks
    {.ext = "epub", .mimetype = SS_LIT("application/epub+zip")},
    {.ext = "mobi", .mimetype = SS_LIT("application/x-mobipocket-ebook")},
    {.ext = "azw", .mimetype = SS_LIT("application/vnd.amazon.ebook")},
    {.ext = "prc", .mimetype = SS_LIT("application/x-mobipocket-ebook")},

    // Microsoft Windows Applications
    {.ext = "wmd", .mimetype = SS_LIT("application/x-ms-wmd")},
    {.ext = "wmz", .mimetype = SS_LIT("application/x-ms-wmz")},
    {.ext = "xbap", .mimetype = SS_LIT("application/x-ms-xbap")},
    {.ext = "mdb", .mimetype = SS_LIT("application/x-msaccess")},
    {.ext = "obd", .mimetype = SS_LIT("application/x-msbinder")},
    {.ext = "crd", .mimetype = SS_LIT("application/x-mscardfile")},
    {.ext = "clp", .mimetype = SS_LIT("application/x-msclip")},
    {.ext = "bat", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "com", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "dll", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "exe", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "msi", .mimetype = SS_LIT("application/x-msdownload")},
    {.ext = "m13", .mimetype = SS_LIT("application/x-msmediaview")},
    {.ext = "m14", .mimetype = SS_LIT("application/x-msmediaview")},
    {.ext = "mvb", .mimetype = SS_LIT("application/x-msmediaview")},

    // Virtual Reality (VR) and Augmented Reality (AR)
    {.ext = "vrml", .mimetype = SS_LIT("model/vrml")},
    {.ext = "glb", .mimetype = SS_LIT("model/gltf-binary")},
    {.ext = "usdz", .mimetype = SS_LIT("model/vnd.usdz+zip")},

    // CAD Files
    {.ext = "dwg", .mimetype = SS_LIT("application/dwg")},
    {.ext = "dxf", .mimetype = SS_LIT("application/dxf")},

    // Geospatial Data
    {.ext = "shp", .mimetype = SS_LIT("application/x-qgis")},
    {.ext = "geojson", .mimetype = SS_LIT("application/geo+json")},

    // configuration
    {.ext = "jsonld", .mimetype = SS_LIT("application/ld+json")},

    // Mathematical Data
    {.ext = "m", .mimetype = SS_LIT("text/x-matlab")},
    {.ext = "r", .mimetype = SS_LIT("application/R")},
    {.ext = "csv", .mimetype = SS_LIT("text/csv")},

    // Chemical Data
    {.ext = "mol", .mimetype = SS_LIT("chemical/x-mdl-molfile")},

    // Medical Imaging
    {.ext = "dicom", .mimetype = SS_LIT("application/dicom")},

    // Configuration Files
    {.ext = "yml", .mimetype = SS_LIT("application/x-yaml")},
    {.ext = "yaml", .mimetype = SS_LIT("application/x-yaml")},
    {.ext = "jsonld", .mimetype = SS_LIT("application/ld+json")},

    // Scientific Data
    {.ext = "netcdf", .mimetype = SS_LIT("application/x-netcdf")},
    {.ext = "fits", .mimetype = SS_LIT("application/fits")},
};

#define MIME_MAPPING_SIZE    (sizeof(mime_entries) / sizeof(mime_entries[0]))
#define DEFAULT_CONTENT_TYPE SS_LIT("application/octet-stream")
#define HASH_TABLE_SIZE      NEXT_POWER_OF_TWO(MIME_MAPPING_SIZE)
#define HASH_TABLE_MASK      (HASH_TABLE_SIZE - 1)

static MimeEntry* hash_table[HASH_TABLE_SIZE] = {0};

// String jdb2 hash function.
static unsigned int hash_func(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + (unsigned)c; /* hash * 33 + c */
    return hash & HASH_TABLE_MASK;                 // Fast alternative to modulo
}

// Initialize hashes for mime types. Must be called before calling
// get_mimetype.
static inline void init_mimetypes() {
    for (size_t i = 0; i < MIME_MAPPING_SIZE; i++) {
        unsigned int hash = hash_func(mime_entries[i].ext);
        mime_entries[i].next = hash_table[hash];
        hash_table[hash] = &mime_entries[i];
    }
}

static inline StrSlice get_mimetype(char* filename) {
    if (!filename) return DEFAULT_CONTENT_TYPE;

    // Find last dot
    char* last_dot = strrchr(filename, '.');
    if (!last_dot) return DEFAULT_CONTENT_TYPE;

    char* extension = last_dot + 1;

    // Max length of extension is 10 + null terminator
    char ext[11];
    strncpy(ext, extension, sizeof(ext) - 1);
    ext[sizeof(ext) - 1] = '\0';

    // Convert to lowercase
    for (char* p = ext; *p; ++p) {
        *p |= 0x20;  // Convert to lowercase (assumes ascii)
    }

    // O(1) lookup
    unsigned int hash = hash_func(ext);

    // Walk the chain.
    for (MimeEntry* entry = hash_table[hash]; entry; entry = entry->next) {
        if (strcmp(ext, entry->ext) == 0) { return entry->mimetype; }
    }
    return DEFAULT_CONTENT_TYPE;
}

#ifdef __cplusplus
}
#endif

#endif  // MIMETYPE_H
