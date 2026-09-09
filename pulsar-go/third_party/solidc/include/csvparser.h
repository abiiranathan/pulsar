/**
 * @file csvparser.h
 * @brief CSV Parser Library: Provides functions for parsing CSV (Comma-Separated Values) data.
 *
 **/
#ifndef __CSV_PARSER_H__
#define __CSV_PARSER_H__

#include <stdbool.h>
#include <stddef.h>

// C++ compatibility
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE 1
#endif

#ifndef CSV_ARENA_BLOCK_SIZE
    #define CSV_ARENA_BLOCK_SIZE (1 << 20)
#endif

#ifndef MAX_FIELD_SIZE
    // Maximum size of the csv line.
    #define MAX_FIELD_SIZE 1024
#endif

// static assert to ensure MAX_FIELD_SIZE is reasonable for stack allocation
#if MAX_FIELD_SIZE > 4096
    #error "MAX_FIELD_SIZE is too large for stack allocation. Please reduce it to 4096 or less."
#endif

/**
 * @brief Opaque structure representing a CSV parser.
 * Create a new CSV parser with csv_reader_new and free it with
 * csv_reader_free. Use csv_reader_parse to parse the CSV data and retrieve all
 * the rows at once. Use csv_reader_parse_async to parse the CSV data and pass
 * each processed row back in a callback. Use csv_reader_getnumrows to get the
 * number of rows in the CSV data. Use csv_reader_setdelim to set the
 * delimiter character for CSV fields.
 *
 * You can redefine before including header the MAX_FIELD_SIZE macro to
 * change the maximum size of the csv line and the CSV_ARENA_BLOCK_SIZE macro
 * to change the size of the arena block.
 */
typedef struct CsvReader CsvReader;

/**
 * @brief Structure representing a CSV row.
 */
typedef struct {
    char** fields;  ///< Array of fields in each row.
    size_t count;   ///< Number of fields in each row.
} Row;

// Async callback for processed rows.
typedef void (*CsvRowCallback)(size_t row_index, Row* row);

/**
 * @brief Create a new CSV reader associated with a filename.
 *
 * This function initializes a new CSV reader and associates it with the
 * given filename.
 *
 * @param filename The filename of the CSV file to parse.
 * @param arena_memory The maximum size of the memory for the parser arena. Pass 0 to use the default
 * or override with -DCSV_ARENA_BLOCK_SIZE.
 * @return A pointer to the created CsvReader, or NULL on failure.
 */
CsvReader* csv_reader_new(const char* filename, size_t arena_memory);

/**
 * @brief Parse the CSV data and retrieve all the rows at once.
 *
 * This function parses the CSV data and returns all the rows as an array of
 * CsvRow structure.
 *
 * The parser file descriptor and stream will automatically be closed.
 * Note that this function allocates an array of all items on the heap
 * that you must free with csv_parser_free.
 *
 * @param reader A pointer to the CsvReader.
 * @return A pointer to the next CsvRow, or NULL if there are no more rows or
 * an error occurs.
 */
Row** csv_reader_parse(CsvReader* reader);

/**
 * @brief Parse the CSV data and pass each processed row back in a callback.
 * Return true from the callback to stop early.
 * The parser file descriptor and stream will automatically be closed.
 *
 * If alloc_max is 0, the parser will allocate all rows at once;
 * otherwise it will allocate alloc_max rows.
 *
 * @param reader A pointer to the CsvReader.
 * @param alloc_max The maximum number of rows to allocate at once.
 * @return void.
 */
void csv_reader_parse_async(CsvReader* reader, CsvRowCallback callback, size_t alloc_max);

/**
 * @brief Get the number of rows in the CSV data.
 *
 * This function returns the total number of rows in the CSV data,
 * excluding empty lines and comments.
 *
 * @param reader A pointer to the CsvReader.
 * @return The number of rows.
 */
size_t csv_reader_numrows(const CsvReader* reader);

/**
 * @brief Free memory used by the CsvReader and CsvRow structures.
 *
 * This function releases the memory used by the CsvReader and any CsvRow
 * structures created with it.
 *
 * @param reader A pointer to the CsvReader.
 */
void csv_reader_free(CsvReader* reader);

struct CsvReaderConfig {
    char delim;
    char quote;
    char comment;
    bool has_header;
    bool skip_header;
};

struct CsvWriterConfig {
    char delim;      // Delimiter character
    char quote;      // Quote character
    char newline;    // Newline character
    bool quote_all;  // Quote all fields
    bool flush;      // Flush the stream after writing each row
    bool append;     // Append to the file if it exists, otherwise create a new file
    bool first_row;  // Whether the current row is the first row written to the
                     // file
};

typedef struct CsvReaderConfig CsvReaderConfig;
typedef struct CsvWriterConfig CsvWriterConfig;

void csv_reader_setconfig(CsvReader* reader, CsvReaderConfig config);
CsvReaderConfig csv_reader_getconfig(CsvReader* reader);

/**
CsvWriter* writer = csvwriter_new("test.csv");
if (!writer) {
    printf("Error creating CSV writer\n");
    return;
}

csvwriter_write_row(writer, (const char*[]){"name", "age"}, 2);
csvwriter_write_row(writer, (const char*[]){"Alice", "25"}, 2);
csvwriter_write_row(writer, (const char*[]){"Bob", "30"}, 2);
csvwriter_write_row(writer, (const char*[]){"Charlie", "35"}, 2);

csvwriter_free(writer);
*/
typedef struct CsvWriter CsvWriter;

#define CsvWriterConfigure(writer, ...)                               \
    csvwriter_setconfig(writer, (CsvWriterConfig){.delim = ',',       \
                                                  .quote = '"',       \
                                                  .newline = '\n',    \
                                                  .quote_all = false, \
                                                  .flush = false,     \
                                                  .first_row = false, \
                                                  __VA_ARGS__})

// Create a new CSV writer associated with a filename.
CsvWriter* csvwriter_new(const char* filename);

// Set the configuration for the CSV writer.
bool csvwriter_write_row(CsvWriter* writer, const char** fields, size_t numfields);

// Free memory used by the CsvWriter and close the file stream.
void csvwriter_free(CsvWriter* writer);

#ifdef __cplusplus
}
#endif

#endif /* __CSV_PARSER_H__ */
