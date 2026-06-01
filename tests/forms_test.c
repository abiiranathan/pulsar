#include <assert.h>
#include <stdio.h>
#include <sys/stat.h>

#include "../include/forms.h"
#include "../include/macros.h"

// Helper function to read a file into memory
char* read_file(const char* filename, size_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *size = (size_t)ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(*size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, *size, file) != *size) {
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return buffer;
}

// Helper function to create a test directory
void create_test_dir() {
    struct stat st = {0};
    if (stat("build", &st) == -1) {
        mkdir("build", 0700);
    }
}

int main() {
    // Create test output directory
    create_test_dir();

    // Test 1: Parse a simple form with fields only
    printf("=== Test 1: Simple form with fields ===\n");
    {
        const char* test_form =
            "--boundary123\r\n"
            "Content-Disposition: form-data; name=\"username\"\r\n\r\n"
            "john_doe\r\n"
            "--boundary123\r\n"
            "Content-Disposition: form-data; name=\"email\"\r\n\r\n"
            "john@example.com\r\n"
            "--boundary123--\r\n";

        MultipartForm form;
        MultipartCode code = multipart_init(&form);
        assert(code == MULTIPART_OK && "Form initialization failed");

        code = multipart_parse(test_form, strlen(test_form), "--boundary123", &form);
        assert(code == MULTIPART_OK && "Form parsing failed");

        // Verify fields
        const char* username = multipart_field_value(&form, "username");
        const char* email    = multipart_field_value(&form, "email");

        printf("Username: %s\n", username);
        printf("Email: %s\n", email);

        assert(username != NULL && "Username field is NULL");
        assert(strcmp(username, "john_doe") == 0 && "Username field value mismatch");
        assert(email != NULL && "Email field is NULL");
        assert(strcmp(email, "john@example.com") == 0 && "Email field value mismatch");

        // Verify no files
        assert(form.num_files == 0 && "Unexpected files in form");

        multipart_cleanup(&form);
    }
    printf("Test 1 completed\n\n");

    // Test 2: Parse a form with file upload
    printf("=== Test 2: Form with file upload ===\n");
    {
        const char* test_form =
            "--boundary123\r\n"
            "Content-Disposition: form-data; name=\"document\"; filename=\"test.txt\"\r\n"
            "Content-Type: text/plain\r\n\r\n"
            "This is a test file content.\n"
            "It has multiple lines.\r\n"
            "--boundary123\r\n"
            "Content-Disposition: form-data; name=\"description\"\r\n\r\n"
            "A sample text file\r\n"
            "--boundary123--\r\n";

        MultipartForm form;
        MultipartCode code = multipart_init(&form);
        assert(code == MULTIPART_OK && "Form initialization failed");

        code = multipart_parse(test_form, strlen(test_form), "--boundary123", &form);
        assert(code == MULTIPART_OK && "Form parsing failed");

        // Verify fields
        const char* description = multipart_field_value(&form, "description");
        printf("Description: %s\n", description);

        assert(description != NULL && "Description field is NULL");
        assert(strcmp(description, "A sample text file") == 0 &&
               "Description field value mismatch");

        // Verify file
        assert(form.num_files == 1 && "Incorrect number of files");

        FileHeader* file = multipart_file(&form, "document");
        assert(file != NULL && "File not found");

        printf("File found: %s (type: %s, size: %zu bytes)\n", file->filename, file->mimetype,
               file->size);

        // Save the file
        bool save_result = multipart_save_file(file, test_form, "build/saved_test.txt");
        assert(save_result && "Failed to save file");
        printf("File saved successfully to build/saved_test.txt\n");

        // Verify file content
        size_t file_size   = 0;
        char* file_content = read_file("build/saved_test.txt", &file_size);
        assert(file_content != NULL && "Failed to read saved file");
        printf("File content:\n%.*s\n", (int)file_size, file_content);
        free(file_content);

        multipart_cleanup(&form);
    }
    printf("Test 2 completed\n\n");

    // Test 3: Parse boundary from header
    printf("=== Test 3: Parse boundary from header ===\n");
    {
        const char* content_type = "multipart/form-data; boundary=boundary123";
        char boundary[256];

        bool parse_result = parse_boundary(content_type, boundary, sizeof(boundary));
        assert(parse_result && "Failed to parse boundary from header");

        printf("Parsed boundary: %s\n", boundary);
        assert(strcmp(boundary, "--boundary123") == 0 && "Boundary parsing mismatch");
    }
    printf("Test 3 completed\n\n");

    printf("All tests completed successfully!\n");
    return 0;
}
