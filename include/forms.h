/**
 * @file forms.h
 * @brief Multipart form data parser implementation
 *
 * This header provides structures and functions for parsing multipart/form-data
 * content as defined in RFC 7578. It handles both file uploads and regular form fields.
 */

#ifndef FORMS_H
#define FORMS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "arena.h"

/**
 * @struct FileHeader
 * @brief Metadata for uploaded files
 *
 * Contains information about uploaded files including their location
 * in the original request body. (It must not be mutated for that matter)
 */
typedef struct FileHeader {
    size_t offset;  ///< Byte offset in original request body
    size_t size;    ///< File size in bytes

    char* filename;    ///< Original filename (arena-allocated)
    char* mimetype;    ///< MIME type (arena-allocated)
    char* field_name;  ///< Form field name (arena-allocated)
} FileHeader;

/**
 * @struct FormField
 * @brief Key-value pair for regular form fields
 */
typedef struct FormField {
    char* name;   ///< Field name (arena-allocated)
    char* value;  ///< Field value (arena-allocated)
} FormField;

/**
 * @struct MultipartForm
 * @brief Container for parsed form data
 */
typedef struct MultipartForm {
    Arena* arena;  ///< Memory arena for all allocations

    FileHeader** files;     ///< Array of file pointers (arena-allocated)
    size_t num_files;       ///< Number of valid files
    size_t files_capacity;  ///< Current array capacity

    FormField* fields;       ///< Array of form fields (arena-allocated)
    size_t num_fields;       ///< Number of valid fields
    size_t fields_capacity;  ///< Current array capacity
} MultipartForm;

/* Error Codes **************************************************************/

/**
 * @enum MpCode
 * @brief Return codes for form parsing operations
 */
typedef enum {
    MULTIPART_OK,            ///< Operation succeeded
    MEMORY_ALLOC_ERROR,      ///< Memory allocation failed
    INVALID_FORM_BOUNDARY,   ///< Malformed boundary marker
    MAX_FILE_SIZE_EXCEEDED,  ///< File exceeds size limit
    EMPTY_FILE_CONTENT,      ///< File has no content
    ARENA_ALLOC_ERROR,       ///< Arena allocation failed
} MultipartCode;

/* Public API **************************************************************/

/**
 * @brief Initialize a multipart form parser
 * @param form Pointer to uninitialized MultipartForm structure
 * @param memory Size of memory arena to allocate (minimum 1024 bytes)
 * @return MpCode indicating success or failure
 *
 * @note This must be called before any other functions on a MultipartForm
 */
MultipartCode multipart_init(MultipartForm* form, size_t memory);

/**
 * @brief Parse multipart form data
 * @param data Raw request body content
 * @param size Length of request body
 * @param boundary Form boundary string (with -- prefix)
 * @param form Initialized MultipartForm structure
 * @return MpCode indicating parse result
 *
 * @note The boundary should match the Content-Type header value
 */
MultipartCode multipart_parse(const char* data, size_t size, const char* boundary, MultipartForm* form);

/**
 * @brief Free all resources associated with a form
 * @param form Form to release
 */
void multipart_cleanup(MultipartForm* form);

/**
 * @brief Get field value by name
 * @param form Parsed form structure
 * @param name Field name to lookup
 * @return Pointer to value or NULL if not found
 */
const char* multipart_field_value(const MultipartForm* form, const char* name);

/**
 * @brief Get file metadata of the first entry that matches the field name
 * @param form Parsed form structure
 * @param field_name Name of file upload field
 * @return FileHeader pointer or NULL if not found
 */
FileHeader* multipart_file(const MultipartForm* form, const char* field_name);

/**
 * @brief Populates indices in multipart files for files matching field_name.
 * @param form Parsed form structure
 * @param field_name Name of file upload field
 * @param out_indices Output array for the matched indices.
 * @param max_indices Array size of out_indices.
 * @return size_t Number of matches in out_indices array.
 */
size_t multipart_files(const MultipartForm* form, const char* field_name, size_t* out_indices,
                       size_t max_indices);

/**
 * @brief Save file contents to disk
 * @param file File metadata from form
 * @param body Original request body
 * @param path Destination path
 * @return true on success, false on failure
 */
bool multipart_save_file(const FileHeader* file, const char* body, const char* path);

/**
 * @brief Get error message string
 * @param error Error code
 * @return Constant string describing error
 */
const char* multipart_error(MultipartCode error);

/* Utility Functions *******************************************************/

/**
 * @brief Extract boundary from Content-Type header
 * @param content_type Header value. Must be null-terminated.
 * @param boundary Output buffer for the boundary.
 * @param size Buffer size for the boundary.
 * @return true if boundary found, false otherwise
 */
bool parse_boundary(const char* content_type, char* boundary, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // FORMS_H
