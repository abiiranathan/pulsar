/**
 * @file hash.h
 * @brief Collection of fast, non-cryptographic hash functions for general-purpose hashing.
 *
 * This library provides several well-known hash functions suitable for hash tables,
 * checksums, and other non-cryptographic applications. For cryptographic hashing,
 * use dedicated cryptographic libraries instead.
 *
 * Available hash functions:
 * - DJB2/DJB2A: Simple and fast, created by Daniel J. Bernstein
 * - FNV-1a: Fowler-Noll-Vo hash, good distribution
 * - SDBM: Used in SDBM database library
 * - ELF: Used in ELF object file format
 * - CRC32: Cyclic redundancy check
 * - MurmurHash3: Excellent distribution and speed
 * - xxHash: Extremely fast (vendored in deps/xxhash, inlined via XXH_INLINE_ALL)
 *
 * NULL-key policy: every function in this header accepts a NULL @p key
 * and returns 0 rather than dereferencing it.  A NULL key is treated as
 * "no data"; callers who need to distinguish it from an empty string
 * must check for NULL before hashing.
 */

#ifndef A02E572A_DD85_4D77_AC81_41037EDE290A
#define A02E572A_DD85_4D77_AC81_41037EDE290A

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef XXH_INLINE_ALL
    #define XXH_INLINE_ALL
#endif

// Include xxhash heaader
#include "../deps/xxhash/xxhash.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DJB2 hash function for null-terminated strings.
 *
 * A simple and effective hash function created by Daniel J. Bernstein.
 * Formula: hash = hash * 33 + c
 *
 * @param key Pointer to null-terminated string
 * @return 32-bit hash value
 *
 * @note This function expects a null-terminated string.
 * @see http://www.cse.yorku.ca/~oz/hash.html
 */
uint32_t solidc_djb2_hash(const void* key);

/**
 * @brief DJB2A hash function (XOR variant) for null-terminated strings.
 *
 * Variant of DJB2 using XOR instead of addition.
 * Formula: hash = hash * 33 ^ c
 *
 * @param key Pointer to null-terminated string
 * @return 32-bit hash value
 *
 * @note This function expects a null-terminated string.
 */
uint32_t solidc_djb2a_hash(const void* key);

/**
 * @brief SDBM hash function for null-terminated strings.
 *
 * Hash function used in the SDBM database library.
 * Formula: hash = c + (hash << 6) + (hash << 16) - hash
 *
 * @param key Pointer to null-terminated string
 * @return 32-bit hash value
 *
 * @note This function expects a null-terminated string.
 */
uint32_t solidc_sdbm_hash(const void* key);

/**
 * @brief FNV-1a 32-bit hash function for null-terminated strings.
 *
 * Fowler-Noll-Vo hash with good distribution properties.
 * Uses XOR-then-multiply approach.
 *
 * @param key Pointer to null-terminated string
 * @return 32-bit hash value
 *
 * @note This function expects a null-terminated string.
 * @see http://www.isthe.com/chongo/tech/comp/fnv/
 */
uint32_t solidc_fnv1a_hash(const void* key);

/**
 * @brief FNV-1a 64-bit hash function for null-terminated strings.
 *
 * 64-bit version of FNV-1a, providing larger hash space.
 * Useful when 32-bit hash collisions are a concern.
 *
 * @param key Pointer to null-terminated string
 * @return 64-bit hash value
 *
 * @note This function expects a null-terminated string.
 * @see http://www.isthe.com/chongo/tech/comp/fnv/
 */
uint64_t solidc_fnv1a_hash64(const void* key);

/**
 * @brief ELF hash function for null-terminated strings.
 *
 * Hash function used in the ELF (Executable and Linkable Format) object file format.
 *
 * @param key Pointer to null-terminated string
 * @return 32-bit hash value
 *
 * @note This function expects a null-terminated string.
 */
uint32_t solidc_elf_hash(const void* key);

/**
 * @brief CRC32 hash function for arbitrary binary data.
 *
 * Cyclic Redundancy Check using the standard IEEE polynomial 0xEDB88320
 * (the classic zlib-compatible CRC32).  Implemented with a slice-by-sixteen
 * table technique; results are bit-identical to the naive bitwise loop
 * but orders of magnitude faster.
 *
 * @param key Pointer to data buffer. May be NULL only when @p len is zero.
 * @param len Length of data in bytes
 * @return 32-bit CRC32 checksum, or 0 if @p key is NULL with nonzero @p len.
 *
 * @note Can handle binary data with embedded null bytes.
 */
uint32_t solidc_crc32_hash(const void* key, size_t len);

/**
 * @brief CRC-32C (Castagnoli) checksum for arbitrary binary data.
 *
 * Uses the Castagnoli polynomial 0x82F63B78 — the one implemented by the
 * x86 `crc32` instruction (SSE4.2) and by iSCSI/ext4/Btrfs.  On capable
 * CPUs this dispatches to the hardware instruction at runtime; elsewhere
 * a slice-by-eight table fallback is used.  This is NOT compatible with
 * solidc_crc32_hash(): different polynomial, different digest.
 *
 * @param key Pointer to data buffer. May be NULL only when @p len is zero.
 * @param len Length of data in bytes
 * @return 32-bit CRC-32C checksum, or 0 if @p key is NULL with nonzero @p len.
 */
uint32_t solidc_crc32c_hash(const void* key, size_t len);

/**
 * @brief MurmurHash3 32-bit hash function.
 *
 * Excellent general-purpose hash with good distribution and performance.
 * Widely used in hash tables and bloom filters.
 *
 * @param key Pointer to data buffer
 * @param len Length of data in bytes
 * @param seed Seed value for hash initialization (use 0 for default)
 * @return 32-bit hash value
 *
 * @note Can handle binary data with embedded null bytes.
 * @see https://en.wikipedia.org/wiki/MurmurHash
 */
uint32_t solidc_murmur_hash(const char* key, uint32_t len, uint32_t seed);

/**
 * @brief xxHash 32-bit function (vendored xxhash, inlined via XXH_INLINE_ALL).
 *
 * Extremely fast hash algorithm that processes at RAM speed limits.
 * Produces identical hashes across all platforms (little/big endian).
 *
 * @param input Pointer to data buffer. May be NULL only when @p len is zero.
 * @param len Length of data in bytes
 * @param seed Seed value for hash initialization
 * @return 32-bit hash value
 *
 * @note This function delegates to XXH32() from the vendored xxhash in deps/.
 * @see https://github.com/Cyan4973/xxHash
 */
static inline uint32_t solidc_XXH32(const void* input, size_t len, uint32_t seed) { return XXH32(input, len, seed); }

#ifdef __cplusplus
}
#endif

#endif /* A02E572A_DD85_4D77_AC81_41037EDE290A */
