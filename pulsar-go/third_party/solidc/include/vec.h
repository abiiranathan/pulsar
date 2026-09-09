/**
 * @file vec_simd.h
 * @brief High-performance SIMD-accelerated vector mathematics library.
 *
 * This library provides a clean separation between storage and computation:
 * - Storage types (Vec2, Vec3, Vec4): Compact, unaligned structs for arrays/serialization
 * - Compute types (SimdVec2, SimdVec3, SimdVec4): 128-bit aligned unions for fast math
 *
 * Design Philosophy:
 * - Store data in Vec* types for memory efficiency
 * - Load into SimdVec* types for computation
 * - Store results back to Vec* types when done
 *
 * Performance Notes:
 * - All SimdVec* types are 16-byte aligned for optimal SIMD performance
 * - Operations leverage SSE/NEON intrinsics through simd.h abstraction layer
 * - Unused components are zero-initialized to prevent undefined behavior
 *
 * @author Your Name
 * @date 2025
 */

#ifndef __VEC_SIMD_H__
#define __VEC_SIMD_H__

#include <stdio.h>
#ifdef __cplusplus
extern "C" {
#endif

#include "simd.h"

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ==================================================
   Storage Types (Unaligned, Standard C Layout)
   ================================================== */

/**
 * @brief 2D vector storage type (8 bytes, unaligned).
 *
 * Ideal for:
 * - Arrays of 2D points/vectors
 * - File I/O and serialization
 * - Interop with other libraries
 *
 * Not suitable for direct computation - use SimdVec2 instead.
 */
typedef struct Vec2 {
    float x;  ///< X component
    float y;  ///< Y component
} Vec2;

/**
 * @brief 3D vector storage type (12 bytes, unaligned).
 *
 * Compact representation without padding. Convert to SimdVec3
 * for computation, which adds padding for SIMD alignment.
 */
typedef struct Vec3 {
    float x;  ///< X component
    float y;  ///< Y component
    float z;  ///< Z component
} Vec3;

/**
 * @brief 4D vector storage type (16 bytes, naturally aligned).
 *
 * Matches SimdVec4 size but not guaranteed to be 16-byte aligned.
 * Still recommended to convert to SimdVec4 for computation.
 */
typedef struct Vec4 {
    float x;  ///< X component
    float y;  ///< Y component
    float z;  ///< Z component
    float w;  ///< W component (also used for homogeneous coordinates)
} Vec4;

/* ==================================================
   Compute Types (128-bit Aligned, Register Mapped)
   ================================================== */

/**
 * @brief 2D vector compute type (16 bytes, 16-byte aligned).
 *
 * Memory Layout:
 * - [0]: x component (used)
 * - [1]: y component (used)
 * - [2]: z component (zero-initialized, unused)
 * - [3]: w component (zero-initialized, unused)
 *
 * The union provides three access methods:
 * 1. v: SIMD register for vectorized operations
 * 2. f32[4]: Array access for iteration/indexing
 * 3. x, y: Named fields for debugging/scalar operations
 *
 * Zero-initialization of unused components ensures safe
 * reuse of 3D/4D operations without garbage data.
 */
typedef union ALIGN(16) SimdVec2 {
    simd_vec_t v;  ///< SIMD register (primary computation interface)
    float f32[4];  ///< Array view (indices 0-1 valid, 2-3 zero)
    struct {
        float x;  ///< X component (debug/scalar access)
        float y;  ///< Y component (debug/scalar access)
    };
} SimdVec2;

/**
 * @brief 3D vector compute type (16 bytes, 16-byte aligned).
 *
 * Memory Layout:
 * - [0]: x component (used)
 * - [1]: y component (used)
 * - [2]: z component (used)
 * - [3]: w component (padding, zero-initialized)
 *
 * The W component acts as padding to maintain 128-bit alignment
 * and is kept at zero for safety when accidentally using 4D operations.
 */
typedef union ALIGN(16) SimdVec3 {
    simd_vec_t v;  ///< SIMD register (primary computation interface)
    float f32[4];  ///< Array view (indices 0-2 valid, 3 padding)
    struct {
        float x;  ///< X component
        float y;  ///< Y component
        float z;  ///< Z component
        float w;  ///< Padding (zero-initialized, do not use)
    };
} SimdVec3;

/**
 * @brief 4D vector compute type (16 bytes, 16-byte aligned).
 *
 * Memory Layout:
 * - [0]: x component (used)
 * - [1]: y component (used)
 * - [2]: z component (used)
 * - [3]: w component (used)
 *
 * All components are active. Commonly used for:
 * - RGBA colors
 * - Quaternions
 * - Homogeneous coordinates (x, y, z, w=1.0)
 * - 4D transformations
 */
typedef union ALIGN(16) SimdVec4 {
    simd_vec_t v;  ///< SIMD register (primary computation interface)
    float f32[4];  ///< Array view (all indices valid)
    struct {
        float x;  ///< X component
        float y;  ///< Y component
        float z;  ///< Z component
        float w;  ///< W component
    };
} SimdVec4;

/* ==================================================
   SimdVec2 Operations
   ================================================== */

/**
 * @brief Prints a Vec2 to stdout
 * @param v The vector to print
 * @param name Optional name to display (can be NULL)
 */
static inline void vec2_print(const Vec2 v, const char* name) {
    if (name) {
        printf("%s: ", name);
    }
    printf("Vec2(%f, %f)\n", v.x, v.y);
}

/**
 * @brief Prints a Vec3 to stdout
 * @param v The vector to print
 * @param name Optional name to display (can be NULL)
 */
static inline void vec3_print(const Vec3 v, const char* name) {
    if (name) {
        printf("%s: ", name);
    }
    printf("Vec3(%.4f, %.4f, %.4f)\n", v.x, v.y, v.z);
}

/**
 * @brief Prints a Vec3 to stdout with no rounding.
 * @param v The vector to print
 * @param name Optional name to display (can be NULL)
 */
static inline void vec3_print_ex(const Vec3 v, const char* name) {
    if (name) {
        printf("%s: ", name);
    }
    printf("Vec3(%f, %f, %f)\n", v.x, v.y, v.z);
}

/**
 * @brief Prints a Vec4 to stdout
 * @param v The vector to print
 * @param name Optional name to display (can be NULL)
 */
static inline void vec4_print(const Vec4 v, const char* name) {
    if (name) {
        printf("%s: ", name);
    }
    printf("Vec4(%.4f, %.4f, %.4f, %.4f)\n", v.x, v.y, v.z, v.w);
}

/**
 * @brief Load a Vec2 into SIMD compute format.
 *
 * Converts unaligned storage format to aligned SIMD format.
 * Z and W components are zero-initialized for safety.
 *
 * @param v The Vec2 storage vector to load
 * @return SimdVec2 ready for SIMD operations
 *
 * @note This is a lightweight operation - compiler often optimizes
 *       this to direct register loads without memory access.
 */
static inline SimdVec2 vec2_load(Vec2 v) {
    SimdVec2 res;
    // Set Z/W to 0.0f to ensure dot products and other operations
    // don't accumulate garbage from uninitialized memory
    res.v = simd_set(v.x, v.y, 0.0f, 0.0f);
    return res;
}

/**
 * @brief Store a SimdVec2 back to Vec2 storage format.
 *
 * Extracts only the X and Y components, discarding padding.
 *
 * @param v The SimdVec2 compute vector to store
 * @return Vec2 storage format (8 bytes)
 *
 * @note Direct union field access is faster than simd_store
 *       for extracting just 2 components.
 */
static inline Vec2 vec2_store(SimdVec2 v) {
    // Direct scalar access from union is cleaner than simd_store for just 2 floats
    return (Vec2){v.x, v.y};
}

/**
 * @brief Add two 2D vectors.
 *
 * Performs component-wise addition: result = a + b
 *
 * @param a First vector
 * @param b Second vector
 * @return SimdVec2 containing (a.x + b.x, a.y + b.y)
 *
 * @note SIMD operation - processes both components simultaneously
 */
static inline SimdVec2 vec2_add(SimdVec2 a, SimdVec2 b) { return (SimdVec2){.v = simd_add(a.v, b.v)}; }

/**
 * @brief Subtract two 2D vectors.
 *
 * Performs component-wise subtraction: result = a - b
 *
 * @param a First vector
 * @param b Second vector
 * @return SimdVec2 containing (a.x - b.x, a.y - b.y)
 */
static inline SimdVec2 vec2_sub(SimdVec2 a, SimdVec2 b) { return (SimdVec2){.v = simd_sub(a.v, b.v)}; }

/**
 * @brief Multiply a 2D vector by a scalar.
 *
 * Scales the vector by uniform factor: result = a * s
 *
 * @param a The vector to scale
 * @param s Scalar multiplier
 * @return SimdVec2 containing (a.x * s, a.y * s)
 *
 * @note The scalar is broadcast to all SIMD lanes for parallel multiplication
 */
static inline SimdVec2 vec2_mul(SimdVec2 a, float s) { return (SimdVec2){.v = simd_mul(a.v, simd_set1(s))}; }

/**
 * @brief Compute dot product of two 2D vectors.
 *
 * Calculates: a.x * b.x + a.y * b.y
 *
 * @param a First vector
 * @param b Second vector
 * @return Scalar dot product
 *
 * @note Uses scalar extraction approach for 2D as horizontal add
 *       overhead is high for just 2 elements. If Z components are
 *       known to be zero, 3D dot could be reused.
 */
static inline float vec2_dot(SimdVec2 a, SimdVec2 b) {
    // 2D dot can use 3D dot if Z=0 (which we ensure on load),
    // but scalar extraction is more efficient for just 2 multiplies.
    // SIMD multiply then scalar extraction:
    // simd_vec_t mul = simd_mul(a.v, b.v);
    // However, direct scalar access is simpler:
    return (a.x * b.x) + (a.y * b.y);
}

/**
 * @brief Compute squared length (magnitude²) of a 2D vector.
 *
 * Calculates: x² + y²
 *
 * @param v The vector
 * @return Squared length (avoids sqrt for performance)
 *
 * @note Use this instead of vec2_length() when comparing distances,
 *       as it avoids the expensive square root operation.
 */
static inline float vec2_length_sq(SimdVec2 v) { return vec2_dot(v, v); }

/**
 * @brief Compute length (magnitude) of a 2D vector.
 *
 * Calculates: √(x² + y²)
 *
 * @param v The vector
 * @return Length (Euclidean norm)
 *
 * @note More expensive than vec2_length_sq() due to sqrt.
 *       Prefer squared length for distance comparisons.
 */
static inline float vec2_length(SimdVec2 v) { return sqrtf(vec2_length_sq(v)); }

/**
 * @brief Normalize a 2D vector to unit length.
 *
 * Returns a vector pointing in the same direction with length 1.
 *
 * @param v The vector to normalize
 * @return Unit vector (length = 1.0)
 *
 * @warning If input vector is zero or near-zero, result is undefined.
 *          Consider checking length before normalizing.
 *
 * @note Reuses simd_normalize3 since Z component is guaranteed zero.
 *       This provides better SIMD utilization than custom 2D normalize.
 */
static inline SimdVec2 vec2_normalize(SimdVec2 v) {
    // Reuse simd_normalize3 since Z=0. This uses rsqrt or proper sqrt
    // depending on platform and gives us proper normalization.
    return (SimdVec2){.v = simd_normalize3(v.v)};
}

/**
 * @brief Rotate a 2D vector by an angle.
 *
 * Rotates counterclockwise by the given angle (in radians).
 * Uses standard 2D rotation matrix:
 *
 * [ cos(θ)  -sin(θ) ]   [ x ]
 * [ sin(θ)   cos(θ) ] × [ y ]
 *
 * Result:
 * - x' = x*cos(θ) - y*sin(θ)
 * - y' = x*sin(θ) + y*cos(θ)
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians (positive = counterclockwise)
 * @return Rotated vector
 *
 * @note Uses SIMD operations for the linear combinations after
 *       computing sin/cos. For batch rotations, consider precomputing
 *       sin/cos to avoid repeated transcendental function calls.
 */
static inline SimdVec2 vec2_rotate(SimdVec2 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    // Broadcast components to all lanes for vectorized linear combination
    simd_vec_t x = simd_splat_x(v.v);
    simd_vec_t y = simd_splat_y(v.v);

    // Rotation matrix columns:
    // col0 = {c, s, 0, 0}  - maps X component
    // col1 = {-s, c, 0, 0} - maps Y component
    simd_vec_t c0 = simd_set(c, s, 0.0f, 0.0f);
    simd_vec_t c1 = simd_set(-s, c, 0.0f, 0.0f);

    // result = x * col0 + y * col1
    return (SimdVec2){.v = simd_add(simd_mul(x, c0), simd_mul(y, c1))};
}

/**
 * @brief Computes the squared distance between two points.
 *
 * Faster than vec2_distance() as it avoids the square root.
 * Useful for distance comparisons (e.g., checking if dist < range).
 *
 * @param a The first point.
 * @param b The second point.
 * @return float The squared Euclidean distance |b - a|^2.
 */
static inline float vec2_distance_sq(SimdVec2 a, SimdVec2 b) { return vec2_length_sq(vec2_sub(b, a)); }

/**
 * @brief Computes the Euclidean distance between two points.
 *
 * @param a The first point.
 * @param b The second point.
 * @return float The distance |b - a|.
 */
static inline float vec2_distance(SimdVec2 a, SimdVec2 b) { return sqrtf(vec2_distance_sq(a, b)); }

/**
 * @brief Linearly interpolates between two vectors.
 *
 * Formula: result = a + (b - a) * t
 *
 * @param a The start vector (t = 0.0).
 * @param b The end vector (t = 1.0).
 * @param t The interpolation factor. Not clamped.
 * @return SimdVec2 The interpolated vector.
 */
static inline SimdVec2 vec2_lerp(SimdVec2 a, SimdVec2 b, float t) {
    // Result = a + (b - a) * t
    SimdVec2 diff = vec2_sub(b, a);
    SimdVec2 part = vec2_mul(diff, t);
    return vec2_add(a, part);
}

/**
 * @brief Projects vector A onto vector B.
 * Formula: B * (dot(A, B) / dot(B, B))
 */
static inline SimdVec2 vec2_project(SimdVec2 a, SimdVec2 b) {
    float b_len_sq = vec2_length_sq(b);
    if (b_len_sq < 1e-6f) return (SimdVec2){{0}};  // Handle zero-length B

    float scale = vec2_dot(a, b) / b_len_sq;
    return vec2_mul(b, scale);
}

/**
 * @brief Gets the component of A perpendicular to B.
 * Formula: A - Project(A, B)
 */
static inline SimdVec2 vec2_reject(SimdVec2 a, SimdVec2 b) { return vec2_sub(a, vec2_project(a, b)); }

/**
 * @brief Returns a vector perpendicular to v (-y, x).
 * Equivalent to a 90-degree counter-clockwise rotation.
 */
static inline SimdVec2 vec2_perpendicular(SimdVec2 v) {
    // 2D Perp is just swapping X and Y and negating one.
    // We can use simd_set for clarity or swizzle macros if defined.
    // X' = -Y, Y' = X
    return (SimdVec2){.v = simd_set(-v.y, v.x, 0.0f, 0.0f)};
}

/* ==================================================
   SimdVec3 Operations
   ================================================== */

/**
 * @brief Load a Vec3 into SIMD compute format.
 *
 * Converts 12-byte storage format to 16-byte aligned SIMD format.
 * W component is zero-initialized as padding.
 *
 * @param v The Vec3 storage vector to load
 * @return SimdVec3 ready for SIMD operations
 */
static inline SimdVec3 vec3_load(Vec3 v) {
    SimdVec3 res;
    // Set W to 0.0f to make accidental dot4/hadd operations safe
    res.v = simd_set(v.x, v.y, v.z, 0.0f);
    return res;
}

/**
 * @brief Store a SimdVec3 back to Vec3 storage format.
 *
 * Extracts X, Y, Z components, discarding W padding.
 *
 * @param v The SimdVec3 compute vector to store
 * @return Vec3 storage format (12 bytes)
 */
static inline Vec3 vec3_store(SimdVec3 v) { return (Vec3){v.x, v.y, v.z}; }

/**
 * @brief Add two 3D vectors.
 *
 * Performs component-wise addition: result = a + b
 *
 * @param a First vector
 * @param b Second vector
 * @return SimdVec3 containing (a.x + b.x, a.y + b.y, a.z + b.z)
 */
static inline SimdVec3 vec3_add(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_add(a.v, b.v)}; }

/**
 * @brief Subtract two 3D vectors.
 *
 * Performs component-wise subtraction: result = a - b
 *
 * @param a First vector
 * @param b Second vector
 * @return SimdVec3 containing (a.x - b.x, a.y - b.y, a.z - b.z)
 */
static inline SimdVec3 vec3_sub(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_sub(a.v, b.v)}; }

/**
 * @brief Multiply a 3D vector by a scalar.
 *
 * Scales the vector uniformly: result = a * s
 *
 * @param a The vector to scale
 * @param s Scalar multiplier
 * @return SimdVec3 containing (a.x * s, a.y * s, a.z * s)
 */
static inline SimdVec3 vec3_mul(SimdVec3 a, float s) { return (SimdVec3){.v = simd_mul(a.v, simd_set1(s))}; }

/**
 * @brief Component-wise multiply two 3D vectors (Hadamard product).
 *
 * Also known as element-wise or Hadamard product.
 * Common uses: scaling, color modulation, per-axis transforms.
 *
 * @param a First vector
 * @param b Second vector
 * @return SimdVec3 containing (a.x * b.x, a.y * b.y, a.z * b.z)
 *
 * @note This is NOT the dot product. Each component is multiplied
 *       independently without summing.
 */
static inline SimdVec3 vec3_scale(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_mul(a.v, b.v)}; }

/**
 * @brief Compute dot product of two 3D vectors.
 *
 * Calculates: a.x * b.x + a.y * b.y + a.z * b.z
 *
 * @param a First vector
 * @param b Second vector
 * @return Scalar dot product
 *
 * @note Geometric interpretation: |a| * |b| * cos(θ)
 *       where θ is the angle between vectors.
 *       - Positive: vectors point in similar direction
 *       - Zero: vectors are perpendicular
 *       - Negative: vectors point in opposite directions
 */
static inline float vec3_dot(SimdVec3 a, SimdVec3 b) { return simd_dot3(a.v, b.v); }

/**
 * @brief Compute cross product of two 3D vectors.
 *
 * Returns a vector perpendicular to both input vectors.
 *
 * Formula:
 * - result.x = a.y * b.z - a.z * b.y
 * - result.y = a.z * b.x - a.x * b.z
 * - result.z = a.x * b.y - a.y * b.x
 *
 * @param a First vector
 * @param b Second vector
 * @return Vector perpendicular to both a and b
 *
 * @note Properties:
 *       - Direction follows right-hand rule
 *       - Magnitude = |a| * |b| * sin(θ)
 *       - a × b = -(b × a) (anti-commutative)
 *       - a × a = 0 (parallel vectors have zero cross product)
 *
 * @note Common uses: computing surface normals, torque,
 *       angular momentum, coordinate system construction.
 */
static inline SimdVec3 vec3_cross(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_cross(a.v, b.v)}; }

/**
 * @brief Compute squared length of a 3D vector.
 *
 * Calculates: x² + y² + z²
 *
 * @param v The vector
 * @return Squared length
 *
 * @note Prefer this over vec3_length() for distance comparisons
 *       to avoid expensive sqrt operation. Since sqrt is monotonic,
 *       comparing squared lengths preserves ordering.
 */
static inline float vec3_length_sq(SimdVec3 v) { return simd_length_sq3(v.v); }

/**
 * @brief Compute length (magnitude) of a 3D vector.
 *
 * Calculates: √(x² + y² + z²)
 *
 * @param v The vector
 * @return Length (Euclidean norm)
 */
static inline float vec3_length(SimdVec3 v) { return simd_length3(v.v); }

/**
 * @brief Normalize a 3D vector to unit length (precise).
 *
 * Returns a vector with same direction but length = 1.0
 * Uses full-precision square root.
 *
 * @param v The vector to normalize
 * @return Unit vector (length = 1.0)
 *
 * @warning If input vector is zero or near-zero, result is undefined.
 *
 * @see vec3_normalize_fast() for faster approximate normalization
 */
static inline SimdVec3 vec3_normalize(SimdVec3 v) { return (SimdVec3){.v = simd_normalize3(v.v)}; }

/**
 * @brief Fast normalize using reciprocal square root (approximate).
 *
 * Uses hardware rsqrt with one Newton-Raphson refinement: measured at
 * ~full float precision (worst-case relative length error < 1e-6 %)
 * while remaining faster than the precise sqrt path.
 *
 * @param v The vector to normalize
 * @return Approximately unit vector
 *
 * @note Recommended for:
 *       - Real-time graphics (lighting, particle systems)
 *       - Cases where slight imprecision is acceptable
 *
 * @note Avoid for:
 *       - Physics simulations (can accumulate error)
 *       - Exact geometric calculations
 *       - Building orthonormal bases
 *
 * @warning SSE rsqrt has ~0.1% error. NEON can be more precise but
 *          still approximate. Use vec3_normalize() for critical paths.
 */
static inline SimdVec3 vec3_normalize_fast(SimdVec3 v) { return (SimdVec3){.v = simd_normalize3_fast(v.v)}; }

/**
 * @brief Computes the squared distance between two points.
 *
 * @param a The first point.
 * @param b The second point.
 * @return float The squared Euclidean distance |b - a|^2.
 */
static inline float vec3_distance_sq(SimdVec3 a, SimdVec3 b) { return vec3_length_sq(vec3_sub(b, a)); }

/**
 * @brief Computes the Euclidean distance between two points.
 *
 * @param a The first point.
 * @param b The second point.
 * @return float The distance |b - a|.
 */
static inline float vec3_distance(SimdVec3 a, SimdVec3 b) { return sqrtf(vec3_distance_sq(a, b)); }

/**
 * @brief Linearly interpolates between two vectors.
 *
 * Formula: result = a + (b - a) * t
 *
 * @param a The start vector.
 * @param b The end vector.
 * @param t The interpolation factor.
 * @return SimdVec3 The interpolated vector.
 */
static inline SimdVec3 vec3_lerp(SimdVec3 a, SimdVec3 b, float t) {
    SimdVec3 diff = vec3_sub(b, a);
    return vec3_add(a, vec3_mul(diff, t));
}

/**
 * @brief Projects vector A onto vector B.
 *
 * Calculates the component of A that is parallel to B.
 *
 * @param a The vector to project.
 * @param b The vector to project onto.
 * @return SimdVec3 The parallel component. Returns zero if B is zero-length.
 */
static inline SimdVec3 vec3_project(SimdVec3 a, SimdVec3 b) {
    float b_len_sq = vec3_length_sq(b);
    if (b_len_sq < 1e-6f) return (SimdVec3){{0}};

    float scale = vec3_dot(a, b) / b_len_sq;
    return vec3_mul(b, scale);
}

/**
 * @brief Calculates the rejection of vector A from vector B.
 *
 * Calculates the component of A that is perpendicular to B.
 *
 * @param a The vector to decompose.
 * @param b The reference direction.
 * @return SimdVec3 The perpendicular component.
 */
static inline SimdVec3 vec3_reject(SimdVec3 a, SimdVec3 b) { return vec3_sub(a, vec3_project(a, b)); }

/**
 * @brief Generates an arbitrary unit vector orthogonal to v.
 *
 * This is useful for constructing basis vectors (e.g., look-at matrices)
 * or getting a tangent vector for a surface normal.
 *
 * Strategy: Crosses `v` with the world axis it is least parallel to
 * (Up or Right) and normalizes the result.
 *
 * @param v The input vector.
 * @return SimdVec3 A normalized vector orthogonal to v.
 */
static inline SimdVec3 vec3_perpendicular(SimdVec3 v) {
    // Strategy: Cross v with the world axis it is LEAST parallel to.
    // If |v.y| < 0.9, cross with Y-axis (0,1,0).
    // Otherwise cross with X-axis (1,0,0).

    // We access scalars here because conditional logic is cleaner in scalar
    // than trying to construct a branchless SIMD mask for this specific logic.
    SimdVec3 axis;
    if (fabsf(v.y) < 0.99f) {
        axis = vec3_load((Vec3){0.0f, 1.0f, 0.0f});  // Up
    } else {
        axis = vec3_load((Vec3){1.0f, 0.0f, 0.0f});  // Right
    }

    return vec3_normalize(vec3_cross(v, axis));
}

/* ==================================================
   SimdVec4 Operations
   ================================================== */

/**
 * @brief Load a Vec4 into SIMD compute format.
 *
 * Converts storage format to aligned SIMD format.
 * All four components are preserved.
 *
 * @param v The Vec4 storage vector to load
 * @return SimdVec4 ready for SIMD operations
 */
static inline SimdVec4 vec4_load(Vec4 v) {
    SimdVec4 res;
    res.v = simd_set(v.x, v.y, v.z, v.w);
    return res;
}

/**
 * @brief Store a SimdVec4 back to Vec4 storage format.
 *
 * @param v The SimdVec4 compute vector to store
 * @return Vec4 storage format (16 bytes)
 */
static inline Vec4 vec4_store(SimdVec4 v) { return (Vec4){v.x, v.y, v.z, v.w}; }

/**
 * @brief Compute length of a 4D vector.
 *
 * Calculates: √(x² + y² + z² + w²)
 *
 * @param v The vector
 * @return Length (Euclidean norm in 4D space)
 */
static inline float vec4_length(SimdVec4 v) { return simd_length4(v.v); }

/**
 * @brief Compute squared length of a 4D vector.
 *
 * Calculates: x² + y² + z² + w²
 *
 * @param v The vector
 * @return Squared length
 */
static inline float vec4_length_sq(SimdVec4 v) { return simd_length_sq4(v.v); }

/**
 * @brief Add two 4D vectors.
 *
 * @param a First vector
 * @param b Second vector
 * @return Component-wise sum
 */
static inline SimdVec4 vec4_add(SimdVec4 a, SimdVec4 b) { return (SimdVec4){.v = simd_add(a.v, b.v)}; }

/**
 * @brief Subtract two 4D vectors.
 *
 * @param a First vector
 * @param b Second vector
 * @return Component-wise difference (a - b)
 */
static inline SimdVec4 vec4_sub(SimdVec4 a, SimdVec4 b) { return (SimdVec4){.v = simd_sub(a.v, b.v)}; }

/**
 * @brief Multiply a 4D vector by a scalar.
 *
 * @param a The vector to scale
 * @param s Scalar multiplier
 * @return Uniformly scaled vector
 */
static inline SimdVec4 vec4_mul(SimdVec4 a, float s) { return (SimdVec4){.v = simd_mul(a.v, simd_set1(s))}; }

/**
 * @brief Divides a 4D vector by a scalar.
 *
 * Safety: Returns a zero vector if s is close to zero (fabs(s) < 1e-8)
 * to prevent Inf/NaN propagation in physics/rendering.
 *
 * @param a The vector to scale (SimdVec4).
 * @param s Scalar divisor.
 * @return Uniformly scaled vector (SimdVec4).
 */
static inline SimdVec4 vec4_div(SimdVec4 a, float s) {
    // Check against a small epsilon to avoid Division by Zero
    if (fabsf(s) < 1e-8f) {
        return (SimdVec4){.v = simd_set_zero()};
    }

    // Multiplication by reciprocal is faster than division
    return vec4_mul(a, 1.0f / s);
}

/**
 * @brief Compute dot product of two 4D vectors.
 *
 * Calculates: a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w
 *
 * @param a First vector
 * @param b Second vector
 * @return Scalar dot product
 *
 * @note Common uses: quaternion operations, homogeneous
 *       coordinate calculations, 4D geometry.
 */
static inline float vec4_dot(SimdVec4 a, SimdVec4 b) { return simd_dot4(a.v, b.v); }

/**
 * @brief Component-wise multiply two 4D vectors (Hadamard product).
 *
 * @param a First vector
 * @param b Second vector
 * @return (a.x * b.x, a.y * b.y, a.z * b.z, a.w * b.w)
 *
 * @note Common uses: RGBA color blending, per-component scaling.
 */
static inline SimdVec4 vec4_scale(SimdVec4 a, SimdVec4 b) { return (SimdVec4){.v = simd_mul(a.v, b.v)}; }

/**
 * @brief Normalize a 4D vector to unit length.
 *
 * @param a The vector to normalize
 * @return Unit vector (length = 1.0)
 *
 * @warning Undefined behavior for zero or near-zero vectors.
 */
static inline SimdVec4 vec4_normalize(SimdVec4 a) { return (SimdVec4){.v = simd_normalize4(a.v)}; }

/* ==================================================
   Missing-Parity Operations (div / min / max / abs / sum / reflect)
   ================================================== */

/**
 * @brief Divides a 2D vector by a scalar (zero-guarded).
 */
static inline SimdVec2 vec2_div(SimdVec2 a, float s) {
    if (fabsf(s) < 1e-8f) {
        return (SimdVec2){.v = simd_set_zero()};
    }
    return vec2_mul(a, 1.0f / s);
}

/**
 * @brief Divides a 3D vector by a scalar (zero-guarded).
 */
static inline SimdVec3 vec3_div(SimdVec3 a, float s) {
    if (fabsf(s) < 1e-8f) {
        return (SimdVec3){.v = simd_set_zero()};
    }
    return vec3_mul(a, 1.0f / s);
}

/** @brief Component-wise minimum of two 2D vectors. */
static inline SimdVec2 vec2_min(SimdVec2 a, SimdVec2 b) { return (SimdVec2){.v = simd_min(a.v, b.v)}; }
/** @brief Component-wise maximum of two 2D vectors. */
static inline SimdVec2 vec2_max(SimdVec2 a, SimdVec2 b) { return (SimdVec2){.v = simd_max(a.v, b.v)}; }
/** @brief Component-wise absolute value of a 2D vector. */
static inline SimdVec2 vec2_abs(SimdVec2 v) { return (SimdVec2){.v = simd_abs(v.v)}; }

/** @brief Component-wise minimum of two 3D vectors. */
static inline SimdVec3 vec3_min(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_min(a.v, b.v)}; }
/** @brief Component-wise maximum of two 3D vectors. */
static inline SimdVec3 vec3_max(SimdVec3 a, SimdVec3 b) { return (SimdVec3){.v = simd_max(a.v, b.v)}; }
/** @brief Component-wise absolute value of a 3D vector. */
static inline SimdVec3 vec3_abs(SimdVec3 v) { return (SimdVec3){.v = simd_abs(v.v)}; }

/**
 * @brief Reflects incident vector I about surface normal N (2D).
 *
 * Formula: R = I - 2 * dot(N, I) * N.  N must be normalized.
 */
static inline SimdVec2 vec2_reflect(SimdVec2 i, SimdVec2 n) { return vec2_sub(i, vec2_mul(n, 2.0f * vec2_dot(n, i))); }

/**
 * @brief Reflects incident vector I about surface normal N (3D).
 *
 * Formula: R = I - 2 * dot(N, I) * N.  N must be normalized.
 * Classic uses: mirror reflections, bounce lighting, billiard physics.
 */
static inline SimdVec3 vec3_reflect(SimdVec3 i, SimdVec3 n) { return vec3_sub(i, vec3_mul(n, 2.0f * vec3_dot(n, i))); }

/**
 * @brief Unsigned angle between two 2D vectors in radians [0, pi].
 *
 * Computed via atan2(|a×b|, a·b), which is numerically stable for
 * near-parallel vectors (unlike acos of the dot product).
 */
static inline float vec2_angle_between(SimdVec2 a, SimdVec2 b) {
    return atan2f(fabsf(a.x * b.y - a.y * b.x), vec2_dot(a, b));
}

/**
 * @brief Unsigned angle between two 3D vectors in radians [0, pi].
 *
 * Computed via atan2(|cross|, dot): numerically stable for
 * near-parallel/near-opposite vectors, unlike acos(clamp(dot)).
 */
static inline float vec3_angle_between(SimdVec3 a, SimdVec3 b) {
    Vec3 c = vec3_store(vec3_cross(a, b));
    return atan2f(sqrtf(c.x * c.x + c.y * c.y + c.z * c.z), vec3_dot(a, b));
}

/* ==================================================
   Rotations (Optimized)
   ================================================== */

/**
 * @brief Rotate a 3D vector around the X-axis.
 *
 * Applies rotation in the YZ-plane; X is preserved.
 * Right-handed convention, counterclockwise looking down +X.
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians
 * @return Rotated vector
 */
static inline SimdVec3 vec3_rotate_x(SimdVec3 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    float ny = v.y * c - v.z * s;
    float nz = v.y * s + v.z * c;
    return (SimdVec3){.v = simd_set(v.x, ny, nz, 0.0f)};
}

/**
 * @brief Rotate a 3D vector around the Y-axis.
 *
 * Applies rotation in the XZ-plane; Y is preserved.
 * Right-handed convention, counterclockwise looking down +Y.
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians
 * @return Rotated vector
 */
static inline SimdVec3 vec3_rotate_y(SimdVec3 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    float nx = v.x * c + v.z * s;
    float nz = -v.x * s + v.z * c;
    return (SimdVec3){.v = simd_set(nx, v.y, nz, 0.0f)};
}

/**
 * @brief Rotate a 3D vector around the Z-axis.
 *
 * Applies rotation in the XY-plane; Z is preserved.
 * Right-handed convention, counterclockwise looking down +Z.
 * Equivalent to 2D rotation lifted into 3D.
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians
 * @return Rotated vector
 */
static inline SimdVec3 vec3_rotate_z(SimdVec3 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    float nx = v.x * c - v.y * s;
    float ny = v.x * s + v.y * c;
    return (SimdVec3){.v = simd_set(nx, ny, v.z, 0.0f)};
}

/**
 * @brief Rotate a 4D vector around the X-axis.
 *
 * Applies rotation in the YZ-plane, preserving X and W components.
 *
 * Rotation matrix (right-handed, counterclockwise when looking down +X):
 * [ 1    0      0    0 ]
 * [ 0  cos θ -sin θ  0 ]
 * [ 0  sin θ  cos θ  0 ]
 * [ 0    0      0    1 ]
 *
 * Result:
 * - x' = x (unchanged)
 * - y' = y * cos(θ) - z * sin(θ)
 * - z' = y * sin(θ) + z * cos(θ)
 * - w' = w (unchanged)
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians (positive = counterclockwise)
 * @return Rotated vector
 *
 * @note Implementation uses scalar math for simplicity as the
 *       complexity of SIMD shuffles/blends for single-axis rotation
 *       often negates performance gains. For batch rotations, consider
 *       matrix multiplication instead.
 */
static inline SimdVec4 vec4_rotate_x(SimdVec4 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    // Apply rotation matrix to Y and Z components
    // X and W are preserved
    float ny = v.y * c - v.z * s;
    float nz = v.y * s + v.z * c;

    return (SimdVec4){.v = simd_set(v.x, ny, nz, v.w)};
}

/**
 * @brief Rotate a 4D vector around the Y-axis.
 *
 * Applies rotation in the XZ-plane, preserving Y and W components.
 *
 * Rotation matrix (right-handed, counterclockwise when looking down +Y):
 * [  cos θ  0  sin θ  0 ]
 * [    0    1    0    0 ]
 * [ -sin θ  0  cos θ  0 ]
 * [    0    0    0    1 ]
 *
 * Result:
 * - x' =  x * cos(θ) + z * sin(θ)
 * - y' = y (unchanged)
 * - z' = -x * sin(θ) + z * cos(θ)
 * - w' = w (unchanged)
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians (positive = counterclockwise)
 * @return Rotated vector
 */
static inline SimdVec4 vec4_rotate_y(SimdVec4 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    // Apply rotation matrix to X and Z components
    // Y and W are preserved
    float nx = v.x * c + v.z * s;
    float nz = -v.x * s + v.z * c;

    return (SimdVec4){.v = simd_set(nx, v.y, nz, v.w)};
}

/**
 * @brief Rotate a 4D vector around the Z-axis.
 *
 * Applies rotation in the XY-plane, preserving Z and W components.
 *
 * Rotation matrix (right-handed, counterclockwise when looking down +Z):
 * [ cos θ -sin θ  0  0 ]
 * [ sin θ  cos θ  0  0 ]
 * [   0      0    1  0 ]
 * [   0      0    0  1 ]
 *
 * Result:
 * - x' = x * cos(θ) - y * sin(θ)
 * - y' = x * sin(θ) + y * cos(θ)
 * - z' = z (unchanged)
 * - w' = w (unchanged)
 *
 * @param v The vector to rotate
 * @param angle Rotation angle in radians (positive = counterclockwise)
 * @return Rotated vector
 *
 * @note This is equivalent to 2D rotation extended to 4D space.
 */
static inline SimdVec4 vec4_rotate_z(SimdVec4 v, float angle) {
    float c = cosf(angle);
    float s = sinf(angle);

    // Apply rotation matrix to X and Y components
    // Z and W are preserved
    float nx = v.x * c - v.y * s;
    float ny = v.x * s + v.y * c;

    return (SimdVec4){.v = simd_set(nx, ny, v.z, v.w)};
}

/* ==================================================
   Utility Functions
   ================================================== */

/**
 * @brief Test if two 3D vectors are equal within epsilon tolerance.
 *
 * Performs component-wise comparison with floating-point tolerance.
 *
 * @param a First vector
 * @param b Second vector
 * @param epsilon Maximum allowed difference per component (e.g., 1e-6f)
 * @return true if all components differ by less than epsilon, false otherwise
 *
 * @note Uses SIMD comparison for all components simultaneously.
 *       The epsilon accounts for floating-point rounding errors.
 *
 * @example
 * Vec3 v1 = {1.0f, 2.0f, 3.0f};
 * Vec3 v2 = {1.00001f, 2.00001f, 3.00001f};
 * bool equal = vec3_equals(v1, v2, 1e-4f); // true
 */
static inline bool vec3_equals(Vec3 a, Vec3 b, float epsilon) {
    // Load with matching Z/W handling to ensure comparison works
    SimdVec3 sa = vec3_load(a);
    SimdVec3 sb = vec3_load(b);
    return simd_equals_eps(sa.v, sb.v, epsilon);
}

/**
 * @brief Test if two 4D vectors are equal within epsilon tolerance.
 *
 * Performs component-wise comparison with floating-point tolerance.
 *
 * @param a First vector
 * @param b Second vector
 * @param epsilon Maximum allowed difference per component
 * @return true if all components differ by less than epsilon
 *
 * @note Particularly useful for comparing quaternions where exact
 *       equality is rare due to normalization and floating-point math.
 */
static inline bool vec4_equals(Vec4 a, Vec4 b, float epsilon) {
    SimdVec4 sa = vec4_load(a);
    SimdVec4 sb = vec4_load(b);
    return simd_equals_eps(sa.v, sb.v, epsilon);
}

/**
 * @brief Computes the squared distance between two 4D vectors.
 *
 * @param a The first vector.
 * @param b The second vector.
 * @return float The squared Euclidean distance |b - a|^2.
 */
static inline float vec4_distance_sq(SimdVec4 a, SimdVec4 b) { return vec4_length_sq(vec4_sub(b, a)); }

/**
 * @brief Computes the Euclidean distance between two 4D vectors.
 *
 * @param a The first vector.
 * @param b The second vector.
 * @return float The distance |b - a|.
 */
static inline float vec4_distance(SimdVec4 a, SimdVec4 b) { return sqrtf(vec4_distance_sq(a, b)); }

/**
 * @brief Linearly interpolates between two 4D vectors.
 *
 * Formula: result = a + (b - a) * t
 *
 * @param a The start vector.
 * @param b The end vector.
 * @param t The interpolation factor.
 * @return SimdVec4 The interpolated vector.
 */
static inline SimdVec4 vec4_lerp(SimdVec4 a, SimdVec4 b, float t) {
    SimdVec4 diff = vec4_sub(b, a);
    return vec4_add(a, vec4_mul(diff, t));
}

/**
 * @brief Projects vector A onto vector B (4D).
 *
 * Calculates the component of A that is parallel to B.
 *
 * @param a The vector to project.
 * @param b The vector to project onto.
 * @return SimdVec4 The parallel component. Returns zero if B is zero-length.
 */
static inline SimdVec4 vec4_project(SimdVec4 a, SimdVec4 b) {
    float b_len_sq = vec4_length_sq(b);
    if (b_len_sq < 1e-6f) return (SimdVec4){{0}};

    float scale = vec4_dot(a, b) / b_len_sq;
    return vec4_mul(b, scale);
}

/**
 * @brief Calculates the rejection of vector A from vector B (4D).
 *
 * Calculates the component of A that is perpendicular to B.
 *
 * @param a The vector to decompose.
 * @param b The reference direction.
 * @return SimdVec4 The perpendicular component.
 */
static inline SimdVec4 vec4_reject(SimdVec4 a, SimdVec4 b) { return vec4_sub(a, vec4_project(a, b)); }

/**
 * @brief Returns a vector with the component-wise minimum of two vectors.
 */
static inline SimdVec4 vec4_min(SimdVec4 a, SimdVec4 b) { return (SimdVec4){.v = simd_min(a.v, b.v)}; }

/**
 * @brief Returns a vector with the component-wise maximum of two vectors.
 */
static inline SimdVec4 vec4_max(SimdVec4 a, SimdVec4 b) { return (SimdVec4){.v = simd_max(a.v, b.v)}; }

/**
 * @brief Returns a vector with the component-wise absolute value.
 */
static inline SimdVec4 vec4_abs(SimdVec4 v) { return (SimdVec4){.v = simd_abs(v.v)}; }

/**
 * @brief Returns the sum of all components (x+y+z+w).
 */
static inline float vec4_sum(SimdVec4 v) { return simd_hadd(v.v); }

/* ==================================================
   Graphics Extensions (neg / clamp / homogeneous / geometry)
   ================================================== */

/** @brief Component-wise negation of a 2D vector. */
static inline SimdVec2 vec2_neg(SimdVec2 v) { return (SimdVec2){.v = simd_neg(v.v)}; }

/** @brief Component-wise negation of a 3D vector. */
static inline SimdVec3 vec3_neg(SimdVec3 v) { return (SimdVec3){.v = simd_neg(v.v)}; }

/** @brief Component-wise negation of a 4D vector. */
static inline SimdVec4 vec4_neg(SimdVec4 v) { return (SimdVec4){.v = simd_neg(v.v)}; }

/**
 * @brief Clamps a 2D vector component-wise into [lo, hi].
 */
static inline SimdVec2 vec2_clamp(SimdVec2 v, float lo, float hi) {
    simd_vec_t vlo = simd_set1(lo);
    simd_vec_t vhi = simd_set1(hi);
    return (SimdVec2){.v = simd_min(simd_max(v.v, vlo), vhi)};
}

/**
 * @brief Clamps a 3D vector component-wise into [lo, hi].
 */
static inline SimdVec3 vec3_clamp(SimdVec3 v, float lo, float hi) {
    simd_vec_t vlo = simd_set1(lo);
    simd_vec_t vhi = simd_set1(hi);
    return (SimdVec3){.v = simd_min(simd_max(v.v, vlo), vhi)};
}

/**
 * @brief Clamps a 4D vector component-wise into [lo, hi].
 */
static inline SimdVec4 vec4_clamp(SimdVec4 v, float lo, float hi) {
    simd_vec_t vlo = simd_set1(lo);
    simd_vec_t vhi = simd_set1(hi);
    return (SimdVec4){.v = simd_min(simd_max(v.v, vlo), vhi)};
}

/** @brief Returns the sum of all components (x+y). */
static inline float vec2_sum(SimdVec2 v) { return v.x + v.y; }

/** @brief Returns the sum of all components (x+y+z). */
static inline float vec3_sum(SimdVec3 v) { return v.x + v.y + v.z; }

/**
 * @brief Promotes a 3D point to homogeneous coordinates (w = 1).
 *
 * A W of 1 means translations in a Mat4 affect this vector, which is
 * what you want for positions/vertices.
 */
static inline Vec4 vec4_from_point(Vec3 p) { return (Vec4){p.x, p.y, p.z, 1.0f}; }

/**
 * @brief Promotes a 3D direction to homogeneous coordinates (w = 0).
 *
 * A W of 0 makes a Mat4's translation column vanish under multiplication,
 * which is what you want for directions/normals.
 */
static inline Vec4 vec4_from_direction(Vec3 d) { return (Vec4){d.x, d.y, d.z, 0.0f}; }

/**
 * @brief Perspective-divides a homogeneous vector back into 3D space.
 *
 * Performs (x/w, y/w, z/w). This is the projection step that maps clip
 * space to NDC after a Mat4_perspective multiply.
 *
 * @param v Homogeneous vector (e.g., clip-space position).
 * @return SimdVec3 NDC position.
 *
 * @warning If w is 0 or very small, the result is undefined (division
 *          happens without guard for speed; callers behind the camera
 *          should be clipped before reaching here).
 */
static inline SimdVec3 vec4_perspective_divide(SimdVec4 v) {
    float inv_w = 1.0f / v.w;
    return (SimdVec3){.v = simd_mul(v.v, simd_set1(inv_w))};
}

/**
 * @brief Scalar triple product a · (b × c).
 *
 * Equals the signed volume of the parallelepiped spanned by a, b, c.
 * Zero when the three vectors are coplanar — useful for back-face and
 * degenerate-triangle detection.
 */
static inline float vec3_triple_product(SimdVec3 a, SimdVec3 b, SimdVec3 c) { return vec3_dot(a, vec3_cross(b, c)); }

/**
 * @brief Computes barycentric coordinates of p relative to triangle (a, b, c).
 *
 * All arguments are 3D points. The returned weights satisfy
 * p ≈ u*a + v*b + w*c with u+v+w = 1 (exact for points in the plane).
 * Weights outside [0,1] indicate the point lies outside the triangle.
 *
 * @param a First triangle vertex (weight .x / u)
 * @param b Second triangle vertex (weight .y / v)
 * @param c Third triangle vertex (weight .z / w)
 * @param p The query point
 * @return Vec3 Barycentric weights (u, v, w)
 */
static inline Vec3 vec3_barycentric(SimdVec3 a, SimdVec3 b, SimdVec3 c, SimdVec3 p) {
    SimdVec3 v0 = vec3_sub(b, a);
    SimdVec3 v1 = vec3_sub(c, a);
    SimdVec3 v2 = vec3_sub(p, a);

    float d00 = vec3_dot(v0, v0);
    float d01 = vec3_dot(v0, v1);
    float d11 = vec3_dot(v1, v1);
    float d20 = vec3_dot(v2, v0);
    float d21 = vec3_dot(v2, v1);

    float denom = d00 * d11 - d01 * d01;
    if (fabsf(denom) < 1e-12f) {
        // Degenerate triangle: weights are meaningless; return centroid weight.
        return (Vec3){1.0f / 3.0f, 1.0f / 3.0f, 1.0f / 3.0f};
    }

    float v = (d11 * d20 - d01 * d21) / denom;
    float w = (d00 * d21 - d01 * d20) / denom;
    float u = 1.0f - v - w;
    return (Vec3){u, v, w};
}

/**
 * @brief Refracts an incident vector through a surface (Snell's law).
 *
 * @param i Incident direction (normalized, pointing toward surface).
 * @param n Surface normal (normalized, pointing against i).
 * @param eta Ratio of indices of refraction (from-side / to-side),
 *            e.g., air-to-water ≈ 1.0/1.33.
 * @return Refracted direction (normalized if i was), or the zero vector
 *         on total internal reflection.
 */
static inline SimdVec3 vec3_refract(SimdVec3 i, SimdVec3 n, float eta) {
    float cosi = -vec3_dot(i, n);
    float k = 1.0f - eta * eta * (1.0f - cosi * cosi);
    if (k < 0.0f) {
        return (SimdVec3){{0}};  // Total internal reflection
    }
    return vec3_add(vec3_mul(i, eta), vec3_mul(n, eta * cosi - sqrtf(k)));
}

/**
 * @brief Flips a normal so it faces against the incident direction.
 *
 * Returns n if dot(n, i) < 0 (already facing), otherwise -n. Common at
 * ray-surface intersections where the geometric normal may point away
 * from the viewer.
 */
static inline SimdVec3 vec3_faceforward(SimdVec3 n, SimdVec3 i) { return (vec3_dot(n, i) < 0.0f) ? n : vec3_neg(n); }

/* ==================================================
   Activation Functions (ML primitives)
   ================================================== */

/** @brief Rectified linear unit applied per component (2D). */
static inline SimdVec2 vec2_relu(SimdVec2 v) {
    return (SimdVec2){{
        v.x > 0.0f ? v.x : 0.0f,
        v.y > 0.0f ? v.y : 0.0f,
    }};
}

/** @brief Rectified linear unit applied per component (3D). */
static inline SimdVec3 vec3_relu(SimdVec3 v) {
    return (SimdVec3){{
        v.x > 0.0f ? v.x : 0.0f,
        v.y > 0.0f ? v.y : 0.0f,
        v.z > 0.0f ? v.z : 0.0f,
    }};
}

/** @brief Rectified linear unit applied per component (4D). */
static inline SimdVec4 vec4_relu(SimdVec4 v) {
    return (SimdVec4){{
        v.x > 0.0f ? v.x : 0.0f,
        v.y > 0.0f ? v.y : 0.0f,
        v.z > 0.0f ? v.z : 0.0f,
        v.w > 0.0f ? v.w : 0.0f,
    }};
}

/** @brief Logistic sigmoid per component: 1 / (1 + e^-x). */
static inline SimdVec2 vec2_sigmoid(SimdVec2 v) {
    return (SimdVec2){{
        1.0f / (1.0f + expf(-v.x)),
        1.0f / (1.0f + expf(-v.y)),
    }};
}

static inline SimdVec3 vec3_sigmoid(SimdVec3 v) {
    return (SimdVec3){{
        1.0f / (1.0f + expf(-v.x)),
        1.0f / (1.0f + expf(-v.y)),
        1.0f / (1.0f + expf(-v.z)),
    }};
}

static inline SimdVec4 vec4_sigmoid(SimdVec4 v) {
    return (SimdVec4){{
        1.0f / (1.0f + expf(-v.x)),
        1.0f / (1.0f + expf(-v.y)),
        1.0f / (1.0f + expf(-v.z)),
        1.0f / (1.0f + expf(-v.w)),
    }};
}

/** @brief Hyperbolic tangent per component. */
static inline SimdVec2 vec2_tanh(SimdVec2 v) { return (SimdVec2){{tanhf(v.x), tanhf(v.y)}}; }
static inline SimdVec3 vec3_tanh(SimdVec3 v) { return (SimdVec3){{tanhf(v.x), tanhf(v.y), tanhf(v.z)}}; }
static inline SimdVec4 vec4_tanh(SimdVec4 v) { return (SimdVec4){{tanhf(v.x), tanhf(v.y), tanhf(v.z), tanhf(v.w)}}; }

/**
 * @brief Softmax over all four lanes of a SimdVec4.
 *
 * Produces a probability distribution (entries >= 0 summing to 1).
 * Numerically stable via max subtraction; typical use is converting a
 * 4-class logit vector into class probabilities.
 */
static inline SimdVec4 vec4_softmax(SimdVec4 v) {
    const float m = fmaxf(fmaxf(v.x, v.y), fmaxf(v.z, v.w));
    const float ex = expf(v.x - m), ey = expf(v.y - m), ez = expf(v.z - m), ew = expf(v.w - m);
    const float inv = 1.0f / (ex + ey + ez + ew);
    return (SimdVec4){{ex * inv, ey * inv, ez * inv, ew * inv}};
}

#ifdef __cplusplus
}
#endif

#endif  // __VEC_SIMD_H__
