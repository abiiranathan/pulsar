/**
 * @file prettytable.c
 * @brief Implementation of generic pretty table printer
 */

#include "../include/prettytable.h"

#include <stdlib.h>
#include <string.h>

// Predefined styles
const prettytable_style PRETTYTABLE_STYLE_BOX = {
    .top_left = "┌",
    .top_mid = "┬",
    .top_right = "┐",
    .mid_left = "├",
    .mid_mid = "┼",
    .mid_right = "┤",
    .bottom_left = "└",
    .bottom_mid = "┴",
    .bottom_right = "┘",
    .horizontal = "─",
    .vertical = "│",
};

const prettytable_style PRETTYTABLE_STYLE_ASCII = {
    .top_left = "+",
    .top_mid = "+",
    .top_right = "+",
    .mid_left = "+",
    .mid_mid = "+",
    .mid_right = "+",
    .bottom_left = "+",
    .bottom_mid = "+",
    .bottom_right = "+",
    .horizontal = "-",
    .vertical = "|",
};

const prettytable_style PRETTYTABLE_STYLE_MINIMAL = {
    .top_left = "",
    .top_mid = "",
    .top_right = "",
    .mid_left = "",
    .mid_mid = " ",
    .mid_right = "",
    .bottom_left = "",
    .bottom_mid = "",
    .bottom_right = "",
    .horizontal = "",
    .vertical = " ",
};

const prettytable_style PRETTYTABLE_STYLE_DOUBLE = {
    .top_left = "╔",
    .top_mid = "╦",
    .top_right = "╗",
    .mid_left = "╠",
    .mid_mid = "╬",
    .mid_right = "╣",
    .bottom_left = "╚",
    .bottom_mid = "╩",
    .bottom_right = "╝",
    .horizontal = "═",
    .vertical = "║",
};

void prettytable_config_init(prettytable_config* config) {
    config->num_rows = 0;
    config->num_cols = 0;
    config->get_header = NULL;
    config->get_cell = NULL;
    config->get_length = NULL;
    config->user_data = NULL;
    config->style = &PRETTYTABLE_STYLE_BOX;
    config->show_header = true;
    config->show_row_count = true;
    config->output = stdout;
}

/**
 * Get display length of text using custom or default strlen.
 */
static inline int get_text_length(const prettytable_config* cfg, const char* text) {
    if (cfg->get_length) {
        return cfg->get_length(cfg->user_data, text);
    }
    return (int)strlen(text);
}

/**
 * Calculate column widths.
 */
static void calculate_column_widths(const prettytable_config* cfg, int* widths) {
    // Initialize with header lengths if showing headers
    if (cfg->show_header && cfg->get_header) {
        for (int col = 0; col < cfg->num_cols; col++) {
            const char* header = cfg->get_header(cfg->user_data, col);
            widths[col] = get_text_length(cfg, header);
        }
    } else {
        for (int col = 0; col < cfg->num_cols; col++) {
            widths[col] = 0;
        }
    }

    // Check each row for maximum width
    for (int row = 0; row < cfg->num_rows; row++) {
        for (int col = 0; col < cfg->num_cols; col++) {
            const char* value = cfg->get_cell(cfg->user_data, row, col);
            int len = get_text_length(cfg, value);
            if (len > widths[col]) {
                widths[col] = len;
            }
        }
    }
}

/**
 * Print a horizontal separator.
 */
static inline void print_separator(const prettytable_config* cfg, const int* widths, const char* left, const char* mid,
                                   const char* right) {
    const prettytable_style* style = cfg->style;
    FILE* out = cfg->output;

    fputs(left, out);
    for (int col = 0; col < cfg->num_cols; col++) {
        // Print horizontal line for column (with padding)
        for (int i = 0; i < widths[col] + 2; i++) {
            fputs(style->horizontal, out);
        }

        if (col < cfg->num_cols - 1) {
            fputs(mid, out);
        }
    }
    fputs(right, out);
    fputc('\n', out);
}

/**
 * Print a data row.
 */
static inline void print_row(const prettytable_config* cfg, const int* widths, const char** values) {
    const prettytable_style* style = cfg->style;
    FILE* out = cfg->output;

    fputs(style->vertical, out);

    for (int col = 0; col < cfg->num_cols; col++) {
        fprintf(out, " %-*s ", widths[col], values[col]);
        fputs(style->vertical, out);
    }
    fputc('\n', out);
}

int prettytable_print(const prettytable_config* config) {
    if (!config || !config->get_cell) {
        return -1;
    }

    if (config->num_cols <= 0) {
        fprintf(config->output ? config->output : stderr, "(No columns)\n");
        return 0;
    }

    const prettytable_config* cfg = config;
    const prettytable_style* style = cfg->style ? cfg->style : &PRETTYTABLE_STYLE_BOX;

    // Allocate single block for widths and row data
    void* block = malloc(sizeof(int) * (size_t)cfg->num_cols + sizeof(char*) * (size_t)cfg->num_cols);
    if (!block) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    int* widths = (int*)block;
    const char** row_data = (const char**)((char*)block + sizeof(int) * (size_t)cfg->num_cols);

    // Calculate column widths
    calculate_column_widths(cfg, widths);

    // Print top border
    print_separator(cfg, widths, style->top_left, style->top_mid, style->top_right);

    // Print header if requested
    if (cfg->show_header && cfg->get_header) {
        for (int col = 0; col < cfg->num_cols; col++) {
            row_data[col] = cfg->get_header(cfg->user_data, col);
        }
        print_row(cfg, widths, row_data);

        // Print header separator
        print_separator(cfg, widths, style->mid_left, style->mid_mid, style->mid_right);
    }

    // Print data rows
    for (int row = 0; row < cfg->num_rows; row++) {
        for (int col = 0; col < cfg->num_cols; col++) {
            row_data[col] = cfg->get_cell(cfg->user_data, row, col);
        }
        print_row(cfg, widths, row_data);
    }

    // Print bottom border
    print_separator(cfg, widths, style->bottom_left, style->bottom_mid, style->bottom_right);

    // Print row count if requested
    if (cfg->show_row_count) {
        fprintf(cfg->output, "(%d row%s)\n", cfg->num_rows, cfg->num_rows == 1 ? "" : "s");
    }

    free(block);
    return 0;
}
