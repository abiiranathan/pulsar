/**
 * @file str_to_num.h
 * @brief String to number conversion utilities.
 */

#ifndef D098E3F2_2EEB_4E1A_892A_156C7D7533C3
#define D098E3F2_2EEB_4E1A_892A_156C7D7533C3

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Define error codes
typedef enum { STO_SUCCESS, STO_OVERFLOW, STO_UNDERFLOW, STO_INVALID } StoError;

/**
 * @brief Converts a string to a uint8_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_u8(const char* str, uint8_t* result);

/**
 * @brief Converts a string to an int8_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_i8(const char* str, int8_t* result);

/**
 * @brief Converts a string to a uint16_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_u16(const char* str, uint16_t* result);

/**
 * @brief Converts a string to an int16_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_i16(const char* str, int16_t* result);

/**
 * @brief Converts a string to a uint32_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_u32(const char* str, uint32_t* result);

/**
 * @brief Converts a string to an int32_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_i32(const char* str, int32_t* result);

/**
 * @brief Converts a string to a uint64_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_u64(const char* str, uint64_t* result);

/**
 * @brief Converts a string to an int64_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_i64(const char* str, int64_t* result);

/**
 * @brief Converts a string to an unsigned long.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_ulong(const char* str, unsigned long* result);

/**
 * @brief Converts a string to a long.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_long(const char* str, long* result);

/**
 * @brief Converts a string to a double.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_double(const char* str, double* result);

/**
 * @brief Converts a string to a float.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_float(const char* str, float* result);

/**
 * @brief Converts a string to an unsigned int.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_uint(const char* str, unsigned int* result);

/** uintptr_t is an unsigned integer type that is capable of storing a data
 * pointer. */
/**
 * @brief Converts a string to a uintptr_t.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_INVALID if invalid input.
 */
StoError str_to_uintptr(const char* str, uintptr_t* result);

/**
 * @brief Converts a string to an int.
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_int(const char* str, int* result);

/**
 * @brief Converts a string to an unsigned long with a specified base.
 *
 * @param str The input string.
 * @param base The base for conversion.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_ulong_base(const char* str, int base, unsigned long* result);

/**
 * @brief Converts a string to a long with a specified base.
 *
 * @param str The input string.
 * @param base The base for conversion.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_long_base(const char* str, int base, long* result);

/**
 * @brief Converts a string to an int with a specified base.
 *
 * @param str The input string.
 * @param base The base for conversion.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_OVERFLOW if out of range,
 * STO_INVALID if invalid input.
 */
StoError str_to_int_base(const char* str, int base, int* result);

/**
 * @brief Converts a string to a boolean.
 * Valid inputs are "true", "false", "yes", "no", "1", "0", "on", "off".
 *
 * @param str The input string.
 * @param result Pointer to the result variable.
 * @return StoError STO_SUCCESS on success, STO_INVALID if invalid input.
 */
StoError str_to_bool(const char* str, bool* result);

/**
 * @brief Returns a human-readable description of a StoError code.
 *
 * @param[in] code Error code returned by the str_to_* functions.
 * @return Static string describing the error; never NULL.
 */
const char* sto_error_string(StoError code);

#ifdef __cplusplus
}
#endif

#endif /* D098E3F2_2EEB_4E1A_892A_156C7D7533C3 */
