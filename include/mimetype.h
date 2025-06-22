#ifndef MIMETYPE_H
#define MIMETYPE_H

#include <ctype.h>
#include <stddef.h>
#include <string.h>

typedef struct MimeEntry {
    const char* ext;
    const char* mimetype;
    struct MimeEntry* next;  // For chaining
} MimeEntry;

static MimeEntry mime_entries[] = {
    // Text mime types
    {.ext = "html", .mimetype = "text/html"},
    {.ext = "htm", .mimetype = "text/html"},
    {.ext = "xhtml", .mimetype = "application/xhtml+xml"},
    {.ext = "php", .mimetype = "application/x-httpd-php"},
    {.ext = "xml", .mimetype = "application/xml"},
    {.ext = "css", .mimetype = "text/css"},
    {.ext = "js", .mimetype = "application/javascript"},
    {.ext = "txt", .mimetype = "text/plain"},
    {.ext = "json", .mimetype = "application/json"},
    {.ext = "csv", .mimetype = "text/csv"},
    {.ext = "md", .mimetype = "text/markdown"},
    {.ext = "webmanifest", .mimetype = "application/manifest+json"},

    // Images
    {.ext = "jpg", .mimetype = "image/jpeg"},
    {.ext = "jpeg", .mimetype = "image/jpeg"},
    {.ext = "png", .mimetype = "image/png"},
    {.ext = "gif", .mimetype = "image/gif"},
    {.ext = "ico", .mimetype = "image/x-icon"},
    {.ext = "svg", .mimetype = "image/svg+xml"},
    {.ext = "bmp", .mimetype = "image/bmp"},
    {.ext = "tiff", .mimetype = "image/tiff"},
    {.ext = "webp", .mimetype = "image/webp"},

    // Documents
    {.ext = "pdf", .mimetype = "application/pdf"},
    {.ext = "doc", .mimetype = "application/msword"},
    {.ext = "docx", .mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {.ext = "pptx", .mimetype = "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {.ext = "xls", .mimetype = "application/vnd.ms-excel"},
    {.ext = "xlsx", .mimetype = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {.ext = "odt", .mimetype = "application/vnd.oasis.opendocument.text"},
    {.ext = "ods", .mimetype = "application/vnd.oasis.opendocument.spreadsheet"},
    {.ext = "odp", .mimetype = "application/vnd.oasis.opendocument.presentation"},
    {.ext = "latex", .mimetype = "application/x-latex"},

    // Programming language source files
    {.ext = "c", .mimetype = "text/x-c"},
    {.ext = "cc", .mimetype = "text/x-c++"},
    {.ext = "cpp", .mimetype = "text/x-c++"},
    {.ext = "c++", .mimetype = "text/x-c++"},
    {.ext = "rs", .mimetype = "text/x-rust"},
    {.ext = "h", .mimetype = "text/x-c"},
    {.ext = "hh", .mimetype = "text/x-c++"},
    {.ext = "hpp", .mimetype = "text/x-c++"},
    {.ext = "h++", .mimetype = "text/x-c++"},
    {.ext = "cs", .mimetype = "text/x-csharp"},
    {.ext = "java", .mimetype = "text/x-java-source"},
    {.ext = "py", .mimetype = "text/x-python"},
    {.ext = "sh", .mimetype = "application/x-shellscript"},
    {.ext = "bat", .mimetype = "application/x-bat"},
    {.ext = "pl", .mimetype = "application/x-perl"},
    {.ext = "rb", .mimetype = "application/x-ruby"},
    {.ext = "php", .mimetype = "application/x-php"},
    {.ext = "go", .mimetype = "text/x-go"},
    {.ext = "swift", .mimetype = "text/x-swift"},
    {.ext = "lua", .mimetype = "text/x-lua"},
    {.ext = "r", .mimetype = "text/x-r"},
    {.ext = "sql", .mimetype = "application/sql"},
    {.ext = "asm", .mimetype = "text/x-asm"},
    {.ext = "s", .mimetype = "text/x-asm"},
    {.ext = "clj", .mimetype = "text/x-clojure"},
    {.ext = "lisp", .mimetype = "text/x-lisp"},
    {.ext = "scm", .mimetype = "text/x-scheme"},
    {.ext = "ss", .mimetype = "text/x-scheme"},
    {.ext = "rkt", .mimetype = "text/x-scheme"},
    {.ext = "jl", .mimetype = "text/x-julia"},
    {.ext = "kt", .mimetype = "text/x-kotlin"},
    {.ext = "dart", .mimetype = "text/x-dart"},
    {.ext = "scala", .mimetype = "text/x-scala"},
    {.ext = "groovy", .mimetype = "text/x-groovy"},
    {.ext = "ts", .mimetype = "text/typescript"},
    {.ext = "tsx", .mimetype = "text/typescript"},
    {.ext = "jsx", .mimetype = "text/jsx"},
    {.ext = "elm", .mimetype = "text/x-elm"},
    {.ext = "erl", .mimetype = "text/x-erlang"},
    {.ext = "hrl", .mimetype = "text/x-erlang"},
    {.ext = "ex", .mimetype = "text/x-elixir"},
    {.ext = "exs", .mimetype = "text/x-elixir"},
    {.ext = "cl", .mimetype = "text/x-common-lisp"},
    {.ext = "lsp", .mimetype = "text/x-common-lisp"},
    {.ext = "f", .mimetype = "text/x-fortran"},
    {.ext = "f77", .mimetype = "text/x-fortran"},
    {.ext = "f90", .mimetype = "text/x-fortran"},
    {.ext = "for", .mimetype = "text/x-fortran"},
    {.ext = "nim", .mimetype = "text/x-nim"},
    {.ext = "v", .mimetype = "text/x-verilog"},
    {.ext = "sv", .mimetype = "text/x-systemverilog"},
    {.ext = "vhd", .mimetype = "text/x-vhdl"},
    {.ext = "dic", .mimetype = "text/x-c"},
    {.ext = "h", .mimetype = "text/x-c"},
    {.ext = "hh", .mimetype = "text/x-c"},
    {.ext = "f", .mimetype = "text/x-fortran"},
    {.ext = "f77", .mimetype = "text/x-fortran"},
    {.ext = "f90", .mimetype = "text/x-fortran"},
    {.ext = "for", .mimetype = "text/x-fortran"},
    {.ext = "java", .mimetype = "text/x-java-source"},
    {.ext = "p", .mimetype = "text/x-pascal"},
    {.ext = "pas", .mimetype = "text/x-pascal"},
    {.ext = "pp", .mimetype = "text/x-pascal"},
    {.ext = "inc", .mimetype = "text/x-pascal"},
    {.ext = "py", .mimetype = "text/x-python"},

    // Other
    {.ext = "etx", .mimetype = "text/x-setext"},
    {.ext = "uu", .mimetype = "text/x-uuencode"},
    {.ext = "vcs", .mimetype = "text/x-vcalendar"},
    {.ext = "vcf", .mimetype = "text/x-vcard"},

    // Video
    {.ext = "mp4", .mimetype = "video/mp4"},
    {.ext = "avi", .mimetype = "video/avi"},
    {.ext = "mkv", .mimetype = "video/x-matroska"},
    {.ext = "mov", .mimetype = "video/quicktime"},
    {.ext = "wmv", .mimetype = "video/x-ms-wmv"},
    {.ext = "flv", .mimetype = "video/x-flv"},
    {.ext = "mpeg", .mimetype = "video/mpeg"},
    {.ext = "webm", .mimetype = "video/webm"},

    // Audio
    {.ext = "mp3", .mimetype = "audio/mpeg"},
    {.ext = "wav", .mimetype = "audio/wav"},
    {.ext = "flac", .mimetype = "audio/flac"},
    {.ext = "aac", .mimetype = "audio/aac"},
    {.ext = "ogg", .mimetype = "audio/ogg"},
    {.ext = "wma", .mimetype = "audio/x-ms-wma"},
    {.ext = "m4a", .mimetype = "audio/m4a"},
    {.ext = "mid", .mimetype = "audio/midi"},

    // Archives
    {.ext = "zip", .mimetype = "application/zip"},
    {.ext = "rar", .mimetype = "application/x-rar-compressed"},
    {.ext = "tar", .mimetype = "application/x-tar"},
    {.ext = "7z", .mimetype = "application/x-7z-compressed"},
    {.ext = "gz", .mimetype = "application/gzip"},
    {.ext = "bz2", .mimetype = "application/x-bzip2"},
    {.ext = "xz", .mimetype = "application/x-xz"},

    // Spreadsheets
    {.ext = "ods", .mimetype = "application/vnd.oasis.opendocument.spreadsheet"},
    {.ext = "csv", .mimetype = "text/csv"},
    {.ext = "tsv", .mimetype = "text/tab-separated-values"},

    // Applications
    {.ext = "exe", .mimetype = "application/x-msdownload"},
    {.ext = "apk", .mimetype = "application/vnd.android.package-archive"},
    {.ext = "dmg", .mimetype = "application/x-apple-diskimage"},

    // Fonts
    {.ext = "ttf", .mimetype = "font/ttf"},
    {.ext = "otf", .mimetype = "font/otf"},
    {.ext = "woff", .mimetype = "font/woff"},
    {.ext = "woff2", .mimetype = "font/woff2"},

    // 3D Models
    {.ext = "obj", .mimetype = "model/obj"},
    {.ext = "stl", .mimetype = "model/stl"},
    {.ext = "gltf", .mimetype = "model/gltf+json"},

    // GIS
    {.ext = "kml", .mimetype = "application/vnd.google-earth.kml+xml"},
    {.ext = "kmz", .mimetype = "application/vnd.google-earth.kmz"},

    // Other
    {.ext = "rss", .mimetype = "application/rss+xml"},
    {.ext = "yaml", .mimetype = "application/x-yaml"},
    {.ext = "ini", .mimetype = "text/plain"},
    {.ext = "cfg", .mimetype = "text/plain"},
    {.ext = "log", .mimetype = "text/plain"},

    // Database Formats
    {.ext = "sqlite", .mimetype = "application/x-sqlite3"},
    {.ext = "sql", .mimetype = "application/sql"},

    // Ebooks
    {.ext = "epub", .mimetype = "application/epub+zip"},
    {.ext = "mobi", .mimetype = "application/x-mobipocket-ebook"},
    {.ext = "azw", .mimetype = "application/vnd.amazon.ebook"},
    {.ext = "prc", .mimetype = "application/x-mobipocket-ebook"},

    // Microsoft Windows Applications
    {.ext = "wmd", .mimetype = "application/x-ms-wmd"},
    {.ext = "wmz", .mimetype = "application/x-ms-wmz"},
    {.ext = "xbap", .mimetype = "application/x-ms-xbap"},
    {.ext = "mdb", .mimetype = "application/x-msaccess"},
    {.ext = "obd", .mimetype = "application/x-msbinder"},
    {.ext = "crd", .mimetype = "application/x-mscardfile"},
    {.ext = "clp", .mimetype = "application/x-msclip"},
    {.ext = "bat", .mimetype = "application/x-msdownload"},
    {.ext = "com", .mimetype = "application/x-msdownload"},
    {.ext = "dll", .mimetype = "application/x-msdownload"},
    {.ext = "exe", .mimetype = "application/x-msdownload"},
    {.ext = "msi", .mimetype = "application/x-msdownload"},
    {.ext = "m13", .mimetype = "application/x-msmediaview"},
    {.ext = "m14", .mimetype = "application/x-msmediaview"},
    {.ext = "mvb", .mimetype = "application/x-msmediaview"},

    // Virtual Reality (VR) and Augmented Reality (AR)
    {.ext = "vrml", .mimetype = "model/vrml"},
    {.ext = "glb", .mimetype = "model/gltf-binary"},
    {.ext = "usdz", .mimetype = "model/vnd.usdz+zip"},

    // CAD Files
    {.ext = "dwg", .mimetype = "application/dwg"},
    {.ext = "dxf", .mimetype = "application/dxf"},

    // Geospatial Data
    {.ext = "shp", .mimetype = "application/x-qgis"},
    {.ext = "geojson", .mimetype = "application/geo+json"},

    // configuration
    {.ext = "jsonld", .mimetype = "application/ld+json"},

    // Mathematical Data
    {.ext = "m", .mimetype = "text/x-matlab"},
    {.ext = "r", .mimetype = "application/R"},
    {.ext = "csv", .mimetype = "text/csv"},

    // Chemical Data
    {.ext = "mol", .mimetype = "chemical/x-mdl-molfile"},

    // Medical Imaging
    {.ext = "dicom", .mimetype = "application/dicom"},

    // Configuration Files
    {.ext = "yml", .mimetype = "application/x-yaml"},
    {.ext = "yaml", .mimetype = "application/x-yaml"},
    {.ext = "jsonld", .mimetype = "application/ld+json"},

    // Scientific Data
    {.ext = "netcdf", .mimetype = "application/x-netcdf"},
    {.ext = "fits", .mimetype = "application/fits"},
};

#define DEFAULT_CONTENT_TYPE "application/octet-stream"
#define MIME_MAPPING_SIZE    (sizeof(mime_entries) / sizeof(mime_entries[0]))

// Macro to compute the next power of two for a given number
#define NEXT_POWER_OF_TWO(n) ((n) == 0 ? 1 : (1 << (32 - __builtin_clz((n) - 1))))
#define HASH_TABLE_SIZE      NEXT_POWER_OF_TWO(MIME_MAPPING_SIZE)

// Power of two check macro
#define IS_POWER_OF_TWO(x) (((x) != 0) && (((x) & ((x) - 1)) == 0))

// Static assertion (C11 or later)
static_assert(IS_POWER_OF_TWO(HASH_TABLE_SIZE), "HASH_TABLE_SIZE must be a power of two");

static MimeEntry* hash_table[HASH_TABLE_SIZE] = {0};

// String hash function.
static unsigned int hash_func(const char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    return hash & (HASH_TABLE_SIZE - 1);  // Fast alternative to modulo
}

// Initialize hashes at runtime
static inline void init_mime_table() {
    for (size_t i = 0; i < MIME_MAPPING_SIZE; i++) {
        unsigned int hash    = hash_func(mime_entries[i].ext);
        mime_entries[i].next = hash_table[hash];
        hash_table[hash]     = &mime_entries[i];
    }
}

static inline const char* get_mimetype(char* filename) {
    static int initialized = 0;
    if (!initialized) {
        init_mime_table();
        initialized = 1;
    }

    if (!filename) return DEFAULT_CONTENT_TYPE;

    // Find last dot
    char* last_dot = strrchr(filename, '.');
    if (!last_dot) return DEFAULT_CONTENT_TYPE;

    char* extension = last_dot + 1;

    // Convert to lowercase
    for (char* p = extension; *p; ++p) {
        *p = tolower((unsigned char)*p);
    }

    // O(1) lookup
    unsigned int hash = hash_func(extension);
    for (MimeEntry* entry = hash_table[hash]; entry; entry = entry->next) {
        if (strcmp(extension, entry->ext) == 0) {
            return entry->mimetype;
        }
    }
    return DEFAULT_CONTENT_TYPE;
}

#endif /* MIMETYPE_H */
