/**
 * @file forms.h
 * @brief Multipart form data parser implementation
 * 
 * This header provides structures and functions for parsing multipart/form-data
 * content as defined in RFC 7578. It handles both file uploads and regular form fields.
 */

#ifndef FORMS_H
#define FORMS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Configuration Constants ***************************************************/

/**
 * @def INITIAL_FIELD_CAPACITY
 * @brief Initial number of form fields to allocate space for
 */
#ifndef INITIAL_FIELD_CAPACITY
#define INITIAL_FIELD_CAPACITY 16
#endif

/**
 * @def INITIAL_FILE_CAPACITY
 * @brief Initial number of files to allocate space for 
 */
#ifndef INITIAL_FILE_CAPACITY
#define INITIAL_FILE_CAPACITY 4
#endif

/**
 * @def MAX_FILE_SIZE
 * @brief Maximum allowed file size (10MB default)
 */
#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE (10 * 1024 * 1024)
#endif

/* Data Structures ***********************************************************/

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

// Opaque structure for the FormArena
typedef struct FormArena FormArena;

/**
 * @struct MultipartForm
 * @brief Container for parsed form data
 */
typedef struct MultipartForm {
    FormArena* arena;  ///< Memory arena for all allocations

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
    MP_OK,                   ///< Operation succeeded
    MEMORY_ALLOC_ERROR,      ///< Memory allocation failed
    INVALID_FORM_BOUNDARY,   ///< Malformed boundary marker
    MAX_FILE_SIZE_EXCEEDED,  ///< File exceeds size limit
    EMPTY_FILE_CONTENT,      ///< File has no content
    ARENA_ALLOC_ERROR,       ///< Arena allocation failed
} MpCode;

/* Public API **************************************************************/

/**
 * @brief Initialize a multipart form parser
 * @param form Pointer to uninitialized MultipartForm structure
 * @param memory Size of memory arena to allocate (minimum 1024 bytes)
 * @return MpCode indicating success or failure
 * 
 * @note This must be called before any other functions on a MultipartForm
 */
MpCode multipart_init(MultipartForm* form, size_t memory);

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
MpCode multipart_parse(const char* data, size_t size, const char* boundary, MultipartForm* form);

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
 * @brief Get file metadata by field name
 * @param form Parsed form structure
 * @param field_name Name of file upload field
 * @return FileHeader pointer or NULL if not found
 */
FileHeader* multipart_file(const MultipartForm* form, const char* field_name);

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
const char* multipart_error(MpCode error);

/* Utility Functions *******************************************************/

/**
 * @brief Extract boundary from request body
 * @param body Request body content
 * @param boundary Output buffer
 * @param size Buffer size
 * @return true if boundary found, false otherwise
 */
bool parse_boundary(const char* body, char* boundary, size_t size);

/**
 * @brief Extract boundary from Content-Type header
 * @param content_type Header value
 * @param boundary Output buffer 
 * @param size Buffer size
 * @return true if boundary found, false otherwise
 */
bool parse_boundary_from_header(const char* content_type, char* boundary, size_t size);

#endif /* FORMS_H */
