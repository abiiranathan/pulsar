#include "../include/csvparser.h"

#include "../include/arena.h"
#include "../include/cstr.h"
#include "../include/str.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct CsvReader {
    FILE* stream;      // file_t pointer corresponding to the file stream.
    Row** rows;        // Array of row pointers
    size_t num_rows;   // Number of rows in csv, excluding empty lines
    char delim;        // Delimiter character
    char quote;        // Quote character
    char comment;      // Comment character
    bool has_header;   // Whether the CSV file has a header
    bool skip_header;  // Whether to skip the header when parsing
    Arena* arena;      // single-threaded arena for memory allocation
} CsvReader;

typedef struct csv_line_params {
    Arena* arena;
    const char* line;
    size_t num_fields;
    size_t rowIndex;
    Row* row;
    char delim;
    char quote;
} csv_line_params;

/** Counts data rows in the file (excluding blank and comment lines), rewinding the stream before returning. */
static size_t line_count(CsvReader* reader);
/** Counts the fields of a CSV line by locating delimiters outside quoted spans. */
static size_t get_num_fields(const char* line, char delim, char quote);
/** Splits one CSV line into its row's field array, duplicating each field into the arena. */
static bool parse_csv_line(csv_line_params* args);

/** Installs the default CSV dialect: ',' delimiter, '"' quotes, '#' comments, header expected but not skipped. */
static inline void set_default_config(CsvReader* reader) {
    reader->delim = ',';
    reader->comment = '#';
    reader->has_header = true;
    reader->skip_header = false;
    reader->quote = '"';
}

/** @brief Creates a CsvReader bound to @p filename, backed by an arena sized from @p arena_memory (or
 * CSV_ARENA_BLOCK_SIZE). Diagnostics are printed to stderr on failure. @param filename The filename of the CSV file to
 * parse (opened for reading). @param arena_memory Maximum size of the parser arena's first block; 0 uses the default.
 * @return A pointer to the created CsvReader (release with csv_reader_free), or NULL on failure. */
CsvReader* csv_reader_new(const char* filename, size_t arena_memory) {
    CsvReader* reader = malloc(sizeof(CsvReader));
    if (!reader) {
        fprintf(stderr, "error allocating memory for CsvReader\n");
        return NULL;
    }

    FILE* stream = fopen(filename, "r");
    if (!stream) {
        fprintf(stderr, "error opening file %s\n", filename);
        free(reader);
        return NULL;
    }

    // Use passed in argument if provided or use default value.
    Arena* arena = arena_create((arena_memory ? arena_memory : CSV_ARENA_BLOCK_SIZE));
    if (!arena) {
        fprintf(stderr, "error creating memory arena\n");
        fclose(stream);
        free(reader);
        return NULL;
    }

    reader->arena = arena;
    reader->num_rows = 0;
    reader->stream = stream;
    reader->rows = NULL;
    set_default_config(reader);
    return reader;
}

// Allocate memory for rows and set num_rows.
/** Allocates the row-pointer array plus one Row per entry from @p arena; everything is reclaimed together by
 * arena_destroy(). @param arena Allocation source. @param num_rows Number of rows to reserve; 0 returns NULL. @return
 * Array of @p num_rows Row pointers, or NULL on arena exhaustion (diagnostic printed). */
static Row** csv_allocate_rows(Arena* arena, size_t num_rows) {
    if (num_rows == 0) {
        return NULL;
    }
    Row** rows = arena_alloc(arena, num_rows * sizeof(Row*));
    if (!rows) {
        fprintf(stderr, "csv_allocate_rows(): arena out of memory\n");
        return NULL;
    }

    for (size_t i = 0; i < num_rows; i++) {
        rows[i] = arena_alloc(arena, sizeof(Row));
        if (!rows[i]) {
            fprintf(stderr, "csv_allocate_rows(): arena_alloc failed on row %zu\n", i);
            return NULL;
        }
    }
    return rows;
}

/** Reads ahead for the first non-blank, non-comment line (trailing whitespace trimmed) to sample the field count, then
 * rewinds the stream so parsing can restart from the top. @param reader Reader whose stream and comment character are
 * used. @param line Buffer receiving the found line. @param line_size Size of @p line. @return true with @p line
 * filled, or false if the file has no valid data/header lines. */
static inline bool read_first_valid_line(CsvReader* reader, char* line, size_t line_size) {
    bool found_valid_line = false;

    while (fgets(line, line_size, reader->stream)) {
        // Trim whitespace from end
        char* end = line + strlen(line) - 1;
        while (end > line && isspace(*end)) {
            end--;
        }

        // Skip empty lines
        if (end == line) {
            continue;
        }

        end[1] = '\0';

        // Skip comment lines
        if (line[0] == reader->comment) {
            continue;
        }

        // This is a valid data/header line
        found_valid_line = true;
        break;
    }

    if (!found_valid_line) {
        return false;
    }

    // Reset the file pointer to the beginning of the file
    fseek(reader->stream, 0, SEEK_SET);
    return true;
}

/** @brief Parses the whole file into reader->rows, which are allocated from the arena up front (row count determined by
 * a pre-pass). Blank lines and comments are skipped, the header optionally so; every parsed row must match the field
 * count of the first valid line. The stream is closed whether parsing succeeds or not. @param reader A pointer to the
 * CsvReader. @return Array of Row* owned by the arena (valid until csv_reader_free), or NULL if there are no rows or an
 * error occurs. */
Row** csv_reader_parse(CsvReader* reader) {
    char line[MAX_FIELD_SIZE] = {0};
    size_t rowIndex = 0;
    bool headerSkipped = false;

    // read num_rows and allocate them on heap.
    reader->num_rows = line_count(reader);
    reader->rows = csv_allocate_rows(reader->arena, reader->num_rows);
    if (!reader->rows) {
        fclose(reader->stream);
        return NULL;
    }

    // Read lines until we find a non-comment, non-empty line to determine field count
    if (!read_first_valid_line(reader, line, sizeof(line))) {
        fclose(reader->stream);
        return NULL;
    }

    // Get the number of fields in the CSV file
    size_t num_fields = get_num_fields(line, reader->delim, reader->quote);
    if (num_fields == 0) {
        fclose(reader->stream);
        return NULL;
    }

    bool parse_success = true;
    while (fgets(line, MAX_FIELD_SIZE, reader->stream) && rowIndex < reader->num_rows) {
        // trim white space from end of line and skip empty lines
        char* end = line + strlen(line) - 1;
        while (end > line && isspace(*end)) {
            end--;
        }

        // If the line is empty, skip it
        if (end == line) {
            continue;
        }

        // Terminate the line with a null character
        end[1] = '\0';

        // skip comment lines
        if (line[0] == reader->comment) {
            continue;
        }

        if (reader->has_header && reader->skip_header && rowIndex == 0 && !headerSkipped) {
            headerSkipped = true;
            continue;
        }

        csv_line_params args = {
            .arena = reader->arena,
            .line = line,
            .rowIndex = rowIndex,
            .row = reader->rows[rowIndex],
            .delim = reader->delim,
            .quote = reader->quote,
            .num_fields = num_fields,
        };

        parse_success = parse_csv_line(&args);
        if (!parse_success) {
            break;
        }
        rowIndex++;
    }

    fclose(reader->stream);

    if (!parse_success) {
        fprintf(stderr, "csv_reader_parse() failed\n");
        fprintf(stderr, "Line: %s\n", line);
        return NULL;
    }

    return reader->rows;
}

/** @brief Streaming variant of csv_reader_parse(): allocates at most @p maxrows rows (0 means all) and hands each
 * parsed row to @p callback as it is produced. Blank lines, comments, and an optional header are skipped; the stream is
 * closed when done. Rows remain valid until csv_reader_free() since they live in the arena. @param reader A pointer to
 * the CsvReader. @param callback Invoked per row with its index; may retain row data until csv_reader_free(). @param
 * alloc_max The maximum number of rows to allocate at once; 0 for unlimited. */
void csv_reader_parse_async(CsvReader* reader, CsvRowCallback callback, size_t maxrows) {
    size_t rowIndex = 0;
    bool headerSkipped = false;
    char line[MAX_FIELD_SIZE] = {0};

    reader->num_rows = line_count(reader);

    // Limit the number of rows to parse if maxrows is set
    reader->num_rows = (maxrows > 0 && maxrows < reader->num_rows) ? maxrows : reader->num_rows;
    reader->rows = csv_allocate_rows(reader->arena, reader->num_rows);
    if (!reader->rows) {
        fclose(reader->stream);
        return;
    }

    if (!read_first_valid_line(reader, line, sizeof(line))) {
        fclose(reader->stream);
        return;
    }

    // Get the number of fields in the CSV file
    size_t num_fields = get_num_fields(line, reader->delim, reader->quote);
    if (num_fields == 0) {
        fprintf(stderr, "Error: no fields found in CSV file\n");
        fclose(reader->stream);
        return;
    }

    while (fgets(line, MAX_FIELD_SIZE, reader->stream) && rowIndex < reader->num_rows) {
        // trim white space from end of line and skip empty lines
        char* end = line + strlen(line) - 1;
        while (end > line && isspace(*end)) {
            end--;
        }

        // If the line is empty, skip it
        if (end == line) {
            continue;
        }

        // Terminate the line with a null character
        end[1] = '\0';

        // skip comment lines
        if (line[0] == reader->comment) {
            continue;
        }

        if (reader->has_header && reader->skip_header && rowIndex == 0 && !headerSkipped) {
            headerSkipped = true;
            continue;
        }

        csv_line_params args = {
            .arena = reader->arena,
            .line = line,
            .rowIndex = rowIndex,
            .row = reader->rows[rowIndex],
            .delim = reader->delim,
            .quote = reader->quote,
            .num_fields = num_fields,
        };

        if (!parse_csv_line(&args)) {
            fprintf(stderr, "csv_reader_parse_async() failed\n");
            break;
        }

        // Pass the processed row to the caller.
        callback(rowIndex, reader->rows[rowIndex]);
        rowIndex++;
    }

    fclose(reader->stream);
}

/** @brief Returns the number of data rows counted by the last parse, excluding empty lines, comments, and a skipped
 * header. @param reader A pointer to the CsvReader. @return The number of rows. */
size_t csv_reader_numrows(const CsvReader* reader) { return reader->num_rows; }

/** @brief Releases all memory: rows live in the arena, so arena_destroy() reclaims them and only the reader struct is
 * freed separately. @param reader A pointer to the CsvReader; NULL is a no-op. */
void csv_reader_free(CsvReader* reader) {
    if (!reader) return;

    // The row are allocated in the arena, so we only need to free the arena.
    arena_destroy(reader->arena);

    free(reader);
    reader = NULL;
}

/** @brief Overrides the reader's dialect. Zero-valued delim/quote/comment keep their current settings; has_header and
 * skip_header are copied verbatim. @param reader A pointer to the CsvReader. @param config New configuration values. */
void csv_reader_setconfig(CsvReader* reader, CsvReaderConfig config) {
    if (config.delim != '\0') {
        reader->delim = config.delim;
    }

    if (config.quote != '\0') {
        reader->quote = config.quote;
    }

    if (config.comment != '\0') {
        reader->comment = config.comment;
    }

    reader->has_header = config.has_header;
    reader->skip_header = config.skip_header;
}

/** @brief Returns a snapshot of the reader's current dialect settings (delimiter, quote, comment, header flags). @param
 * reader A pointer to the CsvReader. @return Copy of the active CsvReaderConfig. */
CsvReaderConfig csv_reader_getconfig(CsvReader* reader) {
    CsvReaderConfig config = {
        .comment = reader->comment,
        .delim = reader->delim,
        .has_header = reader->has_header,
        .skip_header = reader->skip_header,
        .quote = reader->quote,
    };
    return config;
}

/** Counts fields in @p line as one plus the number of delimiters outside quoted spans; quote characters merely toggle
 * quoted state, so an unbalanced quote is not detected here. @param line Line to inspect. @param delim Field delimiter.
 * @param quote Quote character toggling quoted state. @return Number of fields; 0 only for a completely empty line. */
static size_t get_num_fields(const char* line, char delim, char quote) {
    size_t numFields = 0;
    int insideQuotes = 0;

    for (int i = 0; line[i] != '\0'; i++) {
        if (line[i] == quote) {
            insideQuotes = !insideQuotes;  // Toggle insideQuotes flag
        } else if (line[i] == delim && !insideQuotes) {
            numFields++;
        }
    }

    // Add the last field if it is not empty
    if (line[0] != '\0') {
        numFields++;
    }
    return numFields;
}

/** Parses one CSV line into row->fields: splits on unquoted delimiters in place, strips quote characters (a scratch
 * buffer is used only when a field actually contains quotes), trims surrounding whitespace, and duplicates each field
 * into the arena. Fails if the field count differs from args->num_fields or a quote is left unterminated at end of
 * line. @param args Parse parameters: arena, line, dialect characters, target row, expected field count. @return true
 * on success, false after printing a diagnostic to stderr. */
static bool parse_csv_line(csv_line_params* args) {
    Row* row = args->row;
    row->fields = arena_alloc(args->arena, args->num_fields * sizeof(char*));
    if (!row->fields) {
        fprintf(stderr, "ERROR: unable to allocate memory for fields\n");
        return false;
    }

    char** fields = row->fields;
    size_t cnt = 0;
    row->count = 0;

    const char delim = args->delim;
    const char quote = args->quote;
    const char* p = args->line;
    const size_t max_fields = args->num_fields;
    bool in_quotes = false;

    for (;;) {
        /* Locate the field span [f, p): stop at unquoted delimiter or NUL.
         * Delimiters only split while outside quotes, so every field except
         * possibly the last leaves in_quotes == false here. */
        const char* f = p;
        in_quotes = false;
        while (*p) {
            char c = *p;
            if (c == quote) {
                in_quotes = !in_quotes;
            } else if (c == delim && !in_quotes) {
                break;
            }
            p++;
        }

        const char* val_start = f;
        size_t val_len = (size_t)(p - f);

        char scratch[MAX_FIELD_SIZE];
        if (val_len > 0) {
            /* Quote characters are stripped from the stored value; detect
             * their presence with one scan (cheap, usually absent). */
            const char* q = memchr(val_start, quote, val_len);
            if (q != NULL) {
                /* Rare path: compact the span dropping quote characters. */
                size_t w = 0;
                for (size_t r = 0; r < val_len; r++) {
                    if (val_start[r] != quote) {
                        scratch[w++] = val_start[r];
                    }
                }
                val_start = scratch;
                val_len = w;
            }
        }

        /* Trim whitespace on both ends (matches str_trim / isspace). */
        while (val_len > 0 && isspace((unsigned char)val_start[val_len - 1])) {
            val_len--;
        }
        while (val_len > 0 && isspace((unsigned char)*val_start)) {
            val_start++;
            val_len--;
        }

        if (cnt >= max_fields) {
            fprintf(stderr, "ERROR: invalid number of fields in line %zu\n", args->rowIndex);
            return false;
        }
        fields[cnt] = arena_strdupn(args->arena, val_start, val_len);
        if (!fields[cnt]) {
            fprintf(stderr, "ERROR: unable to allocate memory for fields[%zu]\n", cnt);
            return false;
        }
        cnt++;

        if (*p == '\0') {
            break;
        }
        p++; /* skip delimiter */
    }

    /* Unterminated quote at end of line: preserved error from the original
     * implementation.  Only the LAST field can end inside quotes. */
    if (in_quotes) {
        fprintf(stderr, "ERROR: unterminated quoted field:%s in line %zu\n", args->line, args->rowIndex);
        return false;
    }

    if (cnt != max_fields) {
        fprintf(stderr, "ERROR: invalid number of fields in line %zu\n", args->rowIndex);
        return false;
    }
    row->count = cnt;
    return true;
}

#define _CSV_READ_BUFSIZE (64u * 1024u) /* 64 KB — fits comfortably in L2 */

/** Counts data lines in a single 64 KB-buffer pass: comment lines (first character == reader->comment) are skipped,
 * blank (whitespace/CR-only) lines ignored, and the header is excluded when has_header && skip_header. Handles a final
 * line without '\n'. The stream is rewound on entry and exit. @param reader Reader whose stream and dialect are used.
 * @return Number of countable data rows. */
static size_t line_count(CsvReader* reader) {
    size_t lines = 0;
    bool headerSkipped = false;
    bool line_first_char = true; /* first char of a new logical line?    */
    bool skip_this_line = false; /* skip remainder of current line       */
    bool blank_line = true;      /* is the current line blank?           */

    /* One stack buffer; we never hold a reference across a fread() call. */
    char buf[_CSV_READ_BUFSIZE];
    size_t nread;

    rewind(reader->stream);

    while ((nread = fread(buf, 1, sizeof(buf), reader->stream)) > 0) {
        const char* p = buf;
        const char* end = buf + nread;

        while (p < end) {
            /* Find the next newline in the remaining block. */
            const char* nl = (const char*)memchr(p, '\n', (size_t)(end - p));
            const char* chunk_end = nl ? nl + 1 : end;

            /* ---- process characters in [p, chunk_end) ---- */
            for (const char* c = p; c < chunk_end; c++) {
                if (*c == '\n') {
                    /* End of line: count it if it had real content. */
                    if (!skip_this_line && !blank_line) {
                        /* Header skip (only first real data line). */
                        if (reader->has_header && reader->skip_header && !headerSkipped && lines == 0) {
                            headerSkipped = true;
                        } else {
                            lines++;
                        }
                    }
                    /* Reset state for next line. */
                    skip_this_line = false;
                    blank_line = true;
                    line_first_char = true;
                    continue;
                }

                /* Non-newline character. */
                if (skip_this_line) continue;

                if (line_first_char) {
                    line_first_char = false;
                    if (*c == reader->comment) {
                        skip_this_line = true;
                        continue;
                    }
                }

                if (*c != '\r' && (*c != ' ' && *c != '\t')) {
                    blank_line = false;
                }
            }

            p = chunk_end;
        }
    }

    /* Handle last line if it did not end with '\n'. */
    if (!skip_this_line && !blank_line) {
        if (reader->has_header && reader->skip_header && !headerSkipped && lines == 0) {
            /* header only — nothing to count */
        } else {
            lines++;
        }
    }

    rewind(reader->stream);
    return lines;
}

typedef struct CsvWriter {
    FILE* stream;    // file_t pointer corresponding to the file stream.
    char delim;      // Delimiter character
    char quote;      // Quote character
    char newline;    // Newline character
    bool quote_all;  // Quote all fields
    bool flush;      // Flush the stream after writing each row
} CsvWriter;

/** @brief Creates a CsvWriter that truncates/creates @p filename, using the default dialect: ',' delimiter, '"' quotes,
 * '\n' newline, no forced quoting, no per-row flush. Diagnostics go to stderr on failure. @param filename Output file
 * path. @return New CsvWriter (release with csvwriter_free), or NULL on allocation/open failure. */
CsvWriter* csvwriter_new(const char* filename) {
    CsvWriter* writer = malloc(sizeof(CsvWriter));
    if (!writer) {
        fprintf(stderr, "error allocating memory for CsvWriter\n");
        return NULL;
    }

    writer->stream = fopen(filename, "w");
    if (!writer->stream) {
        fprintf(stderr, "error opening file %s\n", filename);
        free(writer);
        return NULL;
    }

    writer->delim = ',';
    writer->quote = '"';
    writer->newline = '\n';
    writer->quote_all = false;
    writer->flush = false;
    return writer;
}

/** Single-pass scan deciding whether a field must be quoted: true when it contains the delimiter, quote, or newline
 * character. */
static inline bool field_needs_quoting(const char* field, char delim, char quote, char newline) {
    for (const char* p = field; *p != '\0'; p++) {
        if (*p == delim || *p == quote || *p == newline) {
            return true;
        }
    }
    return false;
}

/** Writes a quoted field, doubling embedded quote characters per CSV rules; text between quotes is emitted with chunked
 * fwrite calls instead of per-character writes. @param fp File stream to write to. @param field Field content to write.
 * @param quote Quote character to wrap and escape with. @return true on success, false on I/O error. */
static bool write_quoted_field(FILE* fp, const char* field, char quote) {
    if (fputc(quote, fp) == EOF) {
        return false;
    }

    const char* seg = field;
    for (const char* p = field;; p++) {
        if (*p == quote) {
            if (p > seg && fwrite(seg, 1, (size_t)(p - seg), fp) != (size_t)(p - seg)) {
                return false;
            }
            if (fputc(quote, fp) == EOF || fputc(quote, fp) == EOF) {
                return false;
            }
            seg = p + 1;
        } else if (*p == '\0') {
            break;
        }
    }

    size_t tail = strlen(seg);
    if (tail > 0 && fwrite(seg, 1, tail, fp) != tail) {
        return false;
    }

    return fputc(quote, fp) != EOF;
}

/** Writes one field with proper CSV quoting: quoted via write_quoted_field() when @p quote_all is set or the field
 * contains delim/quote/newline, otherwise plain fputs; NULL fields are written as empty strings. @param fp File stream
 * to write to. @param field Field content to write (may be NULL). @param quote_all Whether to quote all fields
 * regardless of content. @param delim The delimiter character. @param quote The quote character. @param newline The
 * newline character. @return true on success, false on I/O error. */
static bool write_single_field(FILE* fp, const char* field, bool quote_all, char delim, char quote, char newline) {
    if (field == NULL) {
        // Handle null field as empty string
        field = "";
    }

    if (quote_all || field_needs_quoting(field, delim, quote, newline)) {
        return write_quoted_field(fp, field, quote);
    } else {
        // Simple case - no quoting needed, use fputs for efficiency
        return fputs(field, fp) != EOF;
    }
}

/** @brief Writes one CSV row: delimiter-separated fields terminated by the writer's newline; numfields == 0 writes a
 * bare newline. Flushes after the row when configured and surfaces deferred stdio errors via ferror. @param writer
 * Pointer to CsvWriter instance. @param fields Array of field strings to write. @param numfields Number of fields in
 * the array. @return true on success, false on error (check errno for details). */
bool csvwriter_write_row(CsvWriter* writer, const char** fields, size_t numfields) {
    // Input validation
    if (writer == NULL) {
        errno = EINVAL;
        return false;
    }

    if (fields == NULL && numfields > 0) {
        errno = EINVAL;
        return false;
    }

    FILE* fp = NULL;

    if (numfields == 0) {
        // Writing empty row - just write newline
        if (fputc(writer->newline, writer->stream) == EOF) {
            return false;
        }
        goto flush_and_exit;
    }

    fp = writer->stream;

    // Check if stream is valid before proceeding
    if (ferror(fp)) {
        return false;
    }

    // Write all fields with delimiters
    for (size_t i = 0; i < numfields; i++) {
        // Write delimiter before all fields except the first
        if (i > 0) {
            if (fputc(writer->delim, fp) == EOF) {
                return false;
            }
        }

        // Write the field content
        if (!write_single_field(fp, fields[i], writer->quote_all, writer->delim, writer->quote, writer->newline)) {
            return false;
        }
    }

    // Write row terminator
    if (fputc(writer->newline, fp) == EOF) {
        return false;
    }

flush_and_exit:
    // Flush if requested
    if (writer->flush && fp) {
        if (fflush(fp) != 0) {
            return false;
        }
    }

    // Final error check
    return !ferror(fp);
}

/** @brief Closes the output file stream and frees the writer. @param writer Writer to free; NULL is a no-op. */
void csvwriter_free(CsvWriter* writer) {
    if (!writer) return;
    if (writer->stream) fclose(writer->stream);
    free(writer);
}

/** Applies writer settings: zero-valued delim/quote keep their current values; quote_all and flush are copied verbatim
 * (newline is not configurable through this call). @param writer Target writer. @param config New configuration values.
 */
void csvwriter_setconfig(CsvWriter* writer, CsvWriterConfig config) {
    if (config.delim != '\0') {
        writer->delim = config.delim;
    }

    if (config.quote != '\0') {
        writer->quote = config.quote;
    }

    writer->quote_all = config.quote_all;
    writer->flush = config.flush;
}
