/**
 * @file prettytable.h
 * @brief Generic pretty table printer library for C
 *
 * A fast, minimal library for printing formatted tables with box-drawing characters.
 * Uses callback functions to support any data source.
 *
 * Example usage:
 *
 *   const char* get_cell(void* data, int row, int col) {
 *       MyData* d = (MyData*)data;
 *       return d->cells[row][col];
 *   }
 *
 *   const char* get_header(void* data, int col) {
 *       const char* headers[] = {"ID", "Name", "Age"};
 *       return headers[col];
 *   }
 *
 *   prettytable_config cfg = {
 *       .num_rows = 3,
 *       .num_cols = 3,
 *       .get_header = get_header,
 *       .get_cell = get_cell,
 *       .user_data = &my_data
 *   };
 *
 *   prettytable_print(&cfg);
 */

#ifndef PRETTYTABLE_H
#define PRETTYTABLE_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback to get header text for a column.
 * @param user_data User-provided context data
 * @param col Column index (0-based)
 * @return Header text (must not be NULL, use "" for empty)
 */
typedef const char* (*prettytable_header_fn)(void* user_data, int col);

/**
 * Callback to get cell value.
 * @param user_data User-provided context data
 * @param row Row index (0-based)
 * @param col Column index (0-based)
 * @return Cell text (must not be NULL, use "" for empty)
 */
typedef const char* (*prettytable_cell_fn)(void* user_data, int row, int col);

/**
 * Optional callback to get custom cell length (for wide chars, etc.)
 * If NULL, strlen() is used.
 * @param user_data User-provided context data
 * @param text Cell text
 * @return Display width of the text
 */
typedef int (*prettytable_strlen_fn)(void* user_data, const char* text);

/**
 * Table border style configuration.
 */
typedef struct {
    const char* top_left;      // ┌
    const char* top_mid;       // ┬
    const char* top_right;     // ┐
    const char* mid_left;      // ├
    const char* mid_mid;       // ┼
    const char* mid_right;     // ┤
    const char* bottom_left;   // └
    const char* bottom_mid;    // ┴
    const char* bottom_right;  // ┘
    const char* horizontal;    // ─
    const char* vertical;      // │
} prettytable_style;

/**
 * Configuration for table printing.
 */
typedef struct {
    int num_rows;                      // Number of data rows
    int num_cols;                      // Number of columns
    prettytable_header_fn get_header;  // Callback for headers
    prettytable_cell_fn get_cell;      // Callback for cell values
    prettytable_strlen_fn get_length;  // Optional: custom length function
    void* user_data;                   // User context passed to callbacks
    const prettytable_style* style;    // Optional: custom border style
    bool show_header;                  // Show header row (default: true)
    bool show_row_count;               // Show row count at bottom (default: true)
    FILE* output;                      // Output stream (default: stdout)
} prettytable_config;

/**
 * Predefined border styles.
 */
extern const prettytable_style PRETTYTABLE_STYLE_BOX;      // ┌─┬─┐ (default)
extern const prettytable_style PRETTYTABLE_STYLE_ASCII;    // +-+-+
extern const prettytable_style PRETTYTABLE_STYLE_MINIMAL;  // No borders
extern const prettytable_style PRETTYTABLE_STYLE_DOUBLE;   // ╔═╦═╗

/**
 * Print a formatted table.
 * @param config Table configuration
 * @return 0 on success, -1 on error
 */
int prettytable_print(const prettytable_config* config);

/**
 * Initialize config with default values.
 * @param config Config to initialize
 */
void prettytable_config_init(prettytable_config* config);

#ifdef __cplusplus
}
#endif

#endif  // PRETTYTABLE_H
