#include <stdio.h>

#include "../include/constants.h"
#include "../include/forms.h"

#define INITIAL_FIELD_CAPACITY 32
#define INITIAL_FILE_CAPACITY  4

/**
 * @enum State
 * @brief Parser state machine states
 */
typedef enum {
    STATE_BOUNDARY,          ///< Looking for boundary marker
    STATE_HEADER,            ///< Parsing headers
    STATE_KEY,               ///< Parsing field name
    STATE_VALUE,             ///< Parsing field value
    STATE_FILENAME,          ///< Parsing filename
    STATE_FILE_MIME_HEADER,  ///< Looking for file mime header
    STATE_MIMETYPE,          ///< Parsing mime type
    STATE_FILE_BODY,         ///< Parsing file contents
} State;

// Helper function to grow the files array
INLINE bool grow_files_array(MultipartForm* form) {
    size_t new_capacity    = form->files_capacity * 2;
    FileHeader** new_files = (FileHeader**)arena_alloc(form->arena, new_capacity * sizeof(FileHeader*));
    if (!new_files) return false;

    // Copy existing pointers
    if (form->files && form->num_files > 0) {
        memcpy(new_files, form->files, form->num_files * sizeof(FileHeader*));
    }

    form->files          = new_files;
    form->files_capacity = new_capacity;
    return true;
}

// Helper function to grow the fields array
INLINE bool grow_fields_array(MultipartForm* form) {
    size_t new_capacity   = form->fields_capacity * 2;
    FormField* new_fields = (FormField*)arena_alloc(form->arena, new_capacity * sizeof(FormField));
    if (!new_fields) return false;

    // Copy existing fields
    if (form->fields && form->num_fields > 0) {
        memcpy(new_fields, form->fields, form->num_fields * sizeof(FormField));
    }

    form->fields          = new_fields;
    form->fields_capacity = new_capacity;
    return true;
}

MpCode multipart_init(MultipartForm* form, size_t memory) {
    if (!form) {
        return MEMORY_ALLOC_ERROR;
    }

    // Make sure we have minimum memory
    static const size_t minMemory = 1024;
    if (memory < minMemory) memory = minMemory;

    memset(form, 0, sizeof(MultipartForm));

    // Create arena
    form->arena = arena_create(memory);
    if (!form->arena) {
        return MEMORY_ALLOC_ERROR;
    }

    // Allocate initial arrays from arena
    form->files = (FileHeader**)arena_alloc(form->arena, INITIAL_FILE_CAPACITY * sizeof(FileHeader*));
    if (!form->files) {
        return ARENA_ALLOC_ERROR;
    }

    form->fields = (FormField*)arena_alloc(form->arena, INITIAL_FIELD_CAPACITY * sizeof(FormField));
    if (!form->fields) {
        return ARENA_ALLOC_ERROR;
    }

    form->files_capacity  = INITIAL_FILE_CAPACITY;
    form->fields_capacity = INITIAL_FIELD_CAPACITY;

    return MP_OK;
}

// Insert file header into form
INLINE bool form_insert_header(MultipartForm* form, FileHeader* header) {
    if (form->num_files >= form->files_capacity) {
        if (!grow_files_array(form)) return false;
    }
    form->files[form->num_files] = header;
    form->num_files++;
    return true;
}

/**
 * Parse a multipart form from the request body.
 * @param data: Request body (without headers). Not assumed to be null-terminated.
 * @param size: Content-Length (size of data in bytes)
 * @param boundary: Null-terminated string for the form boundary.
 * @param form: Pointer to MultipartForm struct to store the parsed form data.
 *              Must be initialized with multipart_init_form() first.
 *
 * @returns: MpCode enum value indicating success or failure.
 */
MpCode multipart_parse(const char* data, size_t size, const char* boundary, MultipartForm* form) {
    if (!data || !boundary || !form || !form->arena) {
        return MEMORY_ALLOC_ERROR;
    }

    size_t boundary_length = strlen(boundary);
    const char* ptr        = data;

    // Temporary variables for parsing
    const char* key_start   = NULL;
    const char* value_start = NULL;

    State state = STATE_BOUNDARY;
    MpCode code = MP_OK;

    // Current file header being built
    FileHeader current_header = {0};

    // Start parsing the form data
    while (ptr < data + size) {
        switch (state) {
            case STATE_BOUNDARY: {
                if (strncmp(ptr, boundary, boundary_length) == 0) {
                    state = STATE_HEADER;
                    ptr += boundary_length;
                    while (ptr < data + size && (*ptr == '-' || *ptr == '\r' || *ptr == '\n')) {
                        ptr++;  // Skip extra characters after boundary
                    }
                } else {
                    ptr++;
                }
            } break;

            case STATE_HEADER: {
                if (strncmp(ptr, "Content-Disposition:", 20) == 0) {
                    ptr = memmem(ptr, size - (ptr - data), "name=\"", 6);
                    if (!ptr) {
                        code = INVALID_FORM_BOUNDARY;
                        goto cleanup;
                    }
                    ptr += 6;  // Skip name=\"
                    key_start = ptr;
                    state     = STATE_KEY;
                } else {
                    ptr++;
                }
            } break;

            case STATE_KEY: {
                if (*ptr == '"' && key_start != NULL) {
                    size_t key_length = ptr - key_start;

                    // Check if this is a file field
                    if (strncmp(ptr, "\"; filename=\"", 13) == 0) {
                        // Allocate field name from arena
                        current_header.field_name = arena_strdup2(form->arena, key_start, key_length);
                        if (!current_header.field_name) {
                            code = ARENA_ALLOC_ERROR;
                            goto cleanup;
                        }
                        ptr = memmem(ptr, size - (ptr - data), "\"; filename=\"", 13);
                        if (!ptr) {
                            code = INVALID_FORM_BOUNDARY;
                            goto cleanup;
                        }
                        ptr += 13;  // Skip "; filename=\""
                        key_start = ptr;
                        state     = STATE_FILENAME;
                    } else {
                        // Regular form field - move to value
                        while (ptr < data + size && *ptr != '\n')
                            ptr++;
                        if (ptr < data + size) ptr++;  // Skip newline

                        // Consume CRLF before value
                        if (ptr + 1 < data + size && *ptr == '\r' && *(ptr + 1) == '\n') {
                            ptr += 2;
                        }

                        value_start = ptr;
                        state       = STATE_VALUE;

                        // Store the key for later use
                        if (form->num_fields >= form->fields_capacity) {
                            if (!grow_fields_array(form)) {
                                code = MEMORY_ALLOC_ERROR;
                                goto cleanup;
                            }
                        }

                        form->fields[form->num_fields].name =
                            arena_strdup2(form->arena, key_start, key_length);
                        if (!form->fields[form->num_fields].name) {
                            code = ARENA_ALLOC_ERROR;
                            goto cleanup;
                        }
                    }
                } else {
                    ptr++;
                }
            } break;

            case STATE_VALUE: {
                if ((strncmp(ptr, "\r\n--", 4) == 0 || strncmp(ptr, boundary, boundary_length) == 0) &&
                    value_start != NULL) {
                    size_t value_length = ptr - value_start;

                    // Allocate value from arena
                    form->fields[form->num_fields].value =
                        arena_strdup2(form->arena, value_start, value_length);
                    if (!form->fields[form->num_fields].value) {
                        code = ARENA_ALLOC_ERROR;
                        goto cleanup;
                    }

                    form->num_fields++;

                    while (ptr < data + size && (*ptr == '\r' || *ptr == '\n')) {
                        ptr++;  // Skip CRLF characters
                    }

                    state = STATE_BOUNDARY;
                } else {
                    ptr++;
                }
            } break;

            case STATE_FILENAME: {
                if (*ptr == '"' && key_start != NULL) {
                    size_t filename_length = ptr - key_start;

                    // Allocate filename from arena
                    current_header.filename = arena_strdup2(form->arena, key_start, filename_length);
                    if (!current_header.filename) {
                        code = ARENA_ALLOC_ERROR;
                        goto cleanup;
                    }

                    // Move to end of line
                    while (ptr < data + size && *ptr != '\n')
                        ptr++;
                    if (ptr < data + size) ptr++;  // Skip newline

                    // Consume CRLF if present
                    if (ptr + 1 < data + size && *ptr == '\r' && *(ptr + 1) == '\n') {
                        ptr += 2;
                    }

                    state = STATE_FILE_MIME_HEADER;
                } else {
                    ptr++;
                }
            } break;

            case STATE_FILE_MIME_HEADER: {
                if (strncmp(ptr, "Content-Type: ", 14) == 0) {
                    ptr += 14;  // Skip "Content-Type: "
                    state = STATE_MIMETYPE;
                } else {
                    ptr++;
                }
            } break;

            case STATE_MIMETYPE: {
                value_start = ptr;

                // Find end of mimetype
                while (ptr < data + size && *ptr != '\r' && *ptr != '\n') {
                    ptr++;
                }

                size_t mimetype_len = ptr - value_start;

                // Allocate mimetype from arena
                current_header.mimetype = arena_strdup2(form->arena, value_start, mimetype_len);
                if (!current_header.mimetype) {
                    code = ARENA_ALLOC_ERROR;
                    goto cleanup;
                }

                // Move to end of line
                while (ptr < data + size && *ptr != '\n')
                    ptr++;
                if (ptr < data + size) ptr++;  // Skip newline

                // Consume CRLF before file body
                while (ptr + 1 < data + size && *ptr == '\r' && *(ptr + 1) == '\n') {
                    ptr += 2;
                }

                // Check for empty file
                if (memcmp(ptr, boundary, boundary_length) == 0) {
                    if (strlen(current_header.filename) == 0) {
                        // Reset current header and continue
                        memset(&current_header, 0, sizeof(FileHeader));
                        state = STATE_BOUNDARY;
                        break;
                    }
                    code = EMPTY_FILE_CONTENT;
                    goto cleanup;
                }

                state = STATE_FILE_BODY;
            } break;

            case STATE_FILE_BODY: {
                current_header.offset = ptr - data;
                size_t haystack_len   = size - current_header.offset;

                // Find end of file content
                char* endptr = (char*)memmem(ptr, haystack_len, boundary, boundary_length);
                if (endptr == NULL) {
                    code = INVALID_FORM_BOUNDARY;
                    goto cleanup;
                }

                size_t endpos    = endptr - data;
                size_t file_size = endpos - current_header.offset;

                // Validate file size
                if (file_size > MAX_FILE_SIZE) {
                    code = MAX_FILE_SIZE_EXCEEDED;
                    goto cleanup;
                }

                current_header.size = file_size;

                // Allocate FileHeader from arena and copy data
                FileHeader* header = (FileHeader*)arena_alloc(form->arena, sizeof(FileHeader));
                if (!header) {
                    code = ARENA_ALLOC_ERROR;
                    goto cleanup;
                }

                *header = current_header;

                // Insert header into form
                if (!form_insert_header(form, header)) {
                    code = MEMORY_ALLOC_ERROR;
                    goto cleanup;
                }

                // Reset current header
                memset(&current_header, 0, sizeof(FileHeader));

                // Move pointer to boundary
                ptr   = endptr;
                state = STATE_BOUNDARY;
            } break;

            default:
                // unreachable
                break;
        }
    }

cleanup:
    if (code != MP_OK) {
        multipart_cleanup(form);
    }
    return code;
}

bool parse_boundary(const char* content_type, char* boundary, size_t size) {
    if (!content_type || !boundary) return false;

    const char* prefix  = "--";
    size_t prefix_len   = 2;  // strlen(prefix)
    size_t total_length = strlen(content_type);

    if (strncasecmp(content_type, "multipart/form-data", 19) != 0) {
        return false;
    }

    char* start = strstr(content_type, "boundary=");
    if (!start) return false;

    // +9 for to move past "boundary="
    size_t length = total_length - ((start + 9) - content_type);

    if (size <= length + prefix_len + 1) return false;

    memcpy(boundary, prefix, prefix_len);
    strncpy(boundary + prefix_len, (start + 9), length);
    boundary[length + prefix_len] = '\0';
    return true;
}

// Free the multipart form and its arena
void multipart_cleanup(MultipartForm* form) {
    if (!form) return;

    if (form->arena) {
        arena_destroy(form->arena);
        form->arena = NULL;
    }

    form->files           = NULL;
    form->fields          = NULL;
    form->num_files       = 0;
    form->num_fields      = 0;
    form->files_capacity  = 0;
    form->fields_capacity = 0;
}

// =============== Fields API ========================

const char* multipart_field_value(const MultipartForm* form, const char* name) {
    if (!form || !name) return NULL;

    for (size_t i = 0; i < form->num_fields; i++) {
        if (form->fields[i].name && strcmp(form->fields[i].name, name) == 0) {
            return form->fields[i].value;
        }
    }
    return NULL;
}

// =============== File API ==========================

FileHeader* multipart_file(const MultipartForm* form, const char* field_name) {
    if (!form || !field_name) return NULL;

    for (size_t i = 0; i < form->num_files; i++) {
        if (form->files[i]->field_name && strcmp(form->files[i]->field_name, field_name) == 0) {
            return form->files[i];
        }
    }
    return NULL;
}

size_t* multipart_get_files(const MultipartForm* form, const char* field_name, size_t* count) {
    if (!form || !field_name || !count) {
        if (count) *count = 0;
        return NULL;
    }

    size_t num_files = 0;
    for (size_t i = 0; i < form->num_files; i++) {
        if (form->files[i]->field_name && strcmp(form->files[i]->field_name, field_name) == 0) {
            num_files++;
        }
    }

    if (num_files == 0) {
        *count = 0;
        return NULL;
    }

    size_t* indices = (size_t*)malloc(num_files * sizeof(size_t));
    if (!indices) {
        *count = 0;
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < form->num_files; i++) {
        if (form->files[i]->field_name && strcmp(form->files[i]->field_name, field_name) == 0) {
            indices[j] = i;
            j++;
        }
    }

    *count = num_files;
    return indices;
}

bool multipart_save_file(const FileHeader* file, const char* body, const char* path) {
    if (!file || !body || !path) return false;

    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("Failed to open file for writing");
        return false;
    }

    size_t n = fwrite(body + file->offset, 1, file->size, f);
    if (n != file->size) {
        perror("Failed to write file to disk");
        fclose(f);
        return false;
    }

    fclose(f);
    return true;
}

const char* multipart_error(MpCode error) {
    switch (error) {
        case MEMORY_ALLOC_ERROR:
            return "Memory allocation failed";
        case INVALID_FORM_BOUNDARY:
            return "Invalid form boundary";
        case MAX_FILE_SIZE_EXCEEDED:
            return "Maximum file size exceeded";
        case EMPTY_FILE_CONTENT:
            return "Empty file content";
        case ARENA_ALLOC_ERROR:
            return "Arena allocation failed";
        case MP_OK:  // fall through
        default:
            return "Success";
    }
}
