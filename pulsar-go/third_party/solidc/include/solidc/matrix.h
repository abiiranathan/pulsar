/**
 * @file matrix.h
 * @brief Matrix operations and mathematical utilities.
 */

#ifndef MATRIX_H
#define MATRIX_H

#ifdef __cplusplus
extern "C" {
#endif

#include "vec.h"

#include <float.h>
#include <stdbool.h>
#include <stdio.h>

/**
 * @struct Mat3
 * @brief A 3x3 matrix for 2D transformations and 3D rotations.
 *
 * Matrix elements are stored in column-major order (OpenGL style):
 * | m[0] m[3] m[6] |
 * | m[1] m[4] m[7] |
 * | m[2] m[5] m[8] |
 */
typedef struct ALIGN(16) Mat3 {
    float m[3][3];  // Column-major storage as m[col][row]
} Mat3;

/**
 * @struct Mat4
 * @brief A 4x4 matrix for 3D transformations.
 *
 * Matrix elements are stored in column-major order (OpenGL style).
 * The union allows accessing data as raw floats or SIMD registers.
 */
typedef struct ALIGN(16) Mat4 {
    union {
        float m[4][4];       // Column-major storage as m[col][row]
        simd_vec_t cols[4];  // SIMD columns
    };
} Mat4;

// Debugging
//================

/**
 * Creates a Mat3 with elements stored in column-major order.
 * @param m00, m01, ... element values in row-major order (as visualised).
 */
static inline Mat3 mat3_new_column_major(float m00, float m01, float m02, float m10, float m11, float m12, float m20,
                                         float m21, float m22) {
    Mat3 mat;
    mat.m[0][0] = m00;
    mat.m[1][0] = m01;
    mat.m[2][0] = m02;
    mat.m[0][1] = m10;
    mat.m[1][1] = m11;
    mat.m[2][1] = m12;
    mat.m[0][2] = m20;
    mat.m[1][2] = m21;
    mat.m[2][2] = m22;
    return mat;
}

// Helper function to create a Mat4 with column-major storage
static inline Mat4 mat4_new_column_major(float m00, float m01, float m02, float m03, float m10, float m11, float m12,
                                         float m13, float m20, float m21, float m22, float m23, float m30, float m31,
                                         float m32, float m33) {
    Mat4 mat;
    mat.m[0][0] = m00;
    mat.m[1][0] = m01;
    mat.m[2][0] = m02;
    mat.m[3][0] = m03;
    mat.m[0][1] = m10;
    mat.m[1][1] = m11;
    mat.m[2][1] = m12;
    mat.m[3][1] = m13;
    mat.m[0][2] = m20;
    mat.m[1][2] = m21;
    mat.m[2][2] = m22;
    mat.m[3][2] = m23;
    mat.m[0][3] = m30;
    mat.m[1][3] = m31;
    mat.m[2][3] = m32;
    mat.m[3][3] = m33;
    return mat;
}

static inline void mat3_print(Mat3 mat, const char* name) {
    printf("%s = \n", name);
    for (int i = 0; i < 3; i++) {
        printf("  [");
        for (int j = 0; j < 3; j++) {
            printf("%8.4f", mat.m[j][i]);
            if (j < 2) printf(", ");
        }
        printf("]\n");
    }
    printf("\n");
}

static inline void mat4_print(Mat4 m, const char* name) {
    printf("%s = \n", name);
    for (int i = 0; i < 4; i++) {
        printf("[ ");
        for (int j = 0; j < 4; j++) {
            printf("%6.3f ", m.m[j][i]);
        }
        printf("]\n");
    }
}

// ======================
// Matrix Initialization
// ======================

static inline Mat3 mat3_identity(void) { return (Mat3){{{1.0f, 0.0f, 0.0f}, {0.0f, 1.0f, 0.0f}, {0.0f, 0.0f, 1.0f}}}; }

static inline bool mat3_equal(Mat3 a, Mat3 b) {
    static float EPSILON = 1e-6f;
    const float* pa = &a.m[0][0];
    const float* pb = &b.m[0][0];

    // Compare first 4 floats (Col 0 and part of Col 1)
    if (!simd_equals_eps(simd_load(pa), simd_load(pb), EPSILON)) return false;

    // Compare next 4 floats
    if (!simd_equals_eps(simd_load(pa + 4), simd_load(pb + 4), EPSILON)) return false;

    // Compare final element (9th float)
    float da = pa[8] - pb[8];
    return fabsf(da) <= EPSILON;
}

static inline bool mat4_equal(Mat4 a, Mat4 b) {
    static float EPSILON = 1e-6f;
    // Unroll comparison for all 4 columns
    return simd_equals_eps(a.cols[0], b.cols[0], EPSILON) && simd_equals_eps(a.cols[1], b.cols[1], EPSILON) &&
           simd_equals_eps(a.cols[2], b.cols[2], EPSILON) && simd_equals_eps(a.cols[3], b.cols[3], EPSILON);
}

static inline Mat3 mat3_diag(Mat3 m) {
    return (Mat3){{{m.m[0][0], 0.0f, 0.0f}, {0.0f, m.m[1][1], 0.0f}, {0.0f, 0.0f, m.m[2][2]}}};
}

static inline Mat4 mat4_identity(void) {
    Mat4 m;
    m.cols[0] = simd_set(1.0f, 0.0f, 0.0f, 0.0f);
    m.cols[1] = simd_set(0.0f, 1.0f, 0.0f, 0.0f);
    m.cols[2] = simd_set(0.0f, 0.0f, 1.0f, 0.0f);
    m.cols[3] = simd_set(0.0f, 0.0f, 0.0f, 1.0f);
    return m;
}

static inline Mat4 mat4_diag(Mat4 m) {
    // Extract diagonals and reform matrix
    // Note: To be purely SIMD efficient we could shuffle, but scalar fallback is clean here.
    Mat4 r;
    r.cols[0] = simd_set(simd_get_x(m.cols[0]), 0, 0, 0);  // X from Col0

    // For other lanes, scalar access is often cleaner than complex shuffles without AVX2
    r.cols[1] = simd_set(0, m.m[1][1], 0, 0);
    r.cols[2] = simd_set(0, 0, m.m[2][2], 0);
    r.cols[3] = simd_set(0, 0, 0, m.m[3][3]);
    return r;
}

// ======================
// Matrix Operations
// ======================

static inline Mat3 mat3_mul(Mat3 a, Mat3 b) {
    Mat3 result;
    // Standard cubic complexity multiplication
    for (int col = 0; col < 3; col++) {
        for (int row = 0; row < 3; row++) {
            result.m[col][row] = 0.0f;
            for (int k = 0; k < 3; k++) {
                result.m[col][row] += a.m[k][row] * b.m[col][k];
            }
        }
    }
    return result;
}

static inline Mat3 mat3_add_scalar(Mat3 m, float scalar) {
    Mat3 result;
    simd_vec_t s_vec = simd_set1(scalar);

    // Vectorized add for first 8 elements
    const float* src = &m.m[0][0];
    float* dst = &result.m[0][0];

    simd_store(dst, simd_add(simd_load(src), s_vec));
    simd_store(dst + 4, simd_add(simd_load(src + 4), s_vec));

    // Tail
    dst[8] = src[8] + scalar;
    return result;
}

static inline Mat3 mat3_add(Mat3 a, Mat3 b) {
    Mat3 result;
    const float* pa = &a.m[0][0];
    const float* pb = &b.m[0][0];
    float* pr = &result.m[0][0];

    // Batch 1 (floats 0-3)
    simd_store(pr, simd_add(simd_load(pa), simd_load(pb)));

    // Batch 2 (floats 4-7)
    simd_store(pr + 4, simd_add(simd_load(pa + 4), simd_load(pb + 4)));

    // Tail
    pr[8] = pa[8] + pb[8];
    return result;
}

static inline Mat3 mat3_scalar_mul(Mat3 m, float scalar) {
    Mat3 result;
    simd_vec_t s_vec = simd_set1(scalar);

    const float* src = &m.m[0][0];
    float* dst = &result.m[0][0];

    simd_store(dst, simd_mul(simd_load(src), s_vec));
    simd_store(dst + 4, simd_mul(simd_load(src + 4), s_vec));
    dst[8] = src[8] * scalar;

    return result;
}

static inline float mat3_determinant(Mat3 m) {
    // Sarrus rule / Co-factor expansion
    return m.m[0][0] * (m.m[1][1] * m.m[2][2] - m.m[2][1] * m.m[1][2]) -
           m.m[0][1] * (m.m[1][0] * m.m[2][2] - m.m[2][0] * m.m[1][2]) +
           m.m[0][2] * (m.m[1][0] * m.m[2][1] - m.m[2][0] * m.m[1][1]);
}

// Matrix LU, Forward Sub, Backward Sub, Exp kept scalar as they are algorithmically complex
// to vectorize without AVX scatter/gather, and usually called infrequently.
static inline bool mat3_lu(Mat3 A, Mat3* L, Mat3* U, Mat3* P) {
    const float tolerance = 1e-6f;
    *U = A;
    // Identity L and P
    *L = mat3_identity();
    *P = mat3_identity();

    for (int k = 0; k < 3; ++k) {
        // Pivot
        int pivot_row = k;
        float max_val = fabsf(U->m[k][k]);
        for (int i = k + 1; i < 3; ++i) {
            float val = fabsf(U->m[k][i]);
            if (val > max_val) {
                max_val = val;
                pivot_row = i;
            }
        }
        if (max_val < tolerance) return false;

        // Swap
        if (pivot_row != k) {
            for (int j = 0; j < 3; ++j) {
                float tmp;
                tmp = U->m[j][k];
                U->m[j][k] = U->m[j][pivot_row];
                U->m[j][pivot_row] = tmp;
                tmp = P->m[j][k];
                P->m[j][k] = P->m[j][pivot_row];
                P->m[j][pivot_row] = tmp;
                if (j < k) {
                    tmp = L->m[j][k];
                    L->m[j][k] = L->m[j][pivot_row];
                    L->m[j][pivot_row] = tmp;
                }
            }
        }
        // Eliminate
        for (int i = k + 1; i < 3; ++i) {
            float factor = U->m[k][i] / U->m[k][k];
            L->m[k][i] = factor;
            for (int j = k; j < 3; ++j) {
                U->m[j][i] -= factor * U->m[j][k];
            }
        }
    }
    return true;
}

static inline Vec3 forward_substitution_mat3(Mat3 L, Vec3 b) {
    Vec3 x;
    x.x = b.x / L.m[0][0];
    x.y = (b.y - L.m[0][1] * x.x) / L.m[1][1];
    x.z = (b.z - L.m[0][2] * x.x - L.m[1][2] * x.y) / L.m[2][2];
    return x;
}

static inline Vec3 backward_substitution_mat3(Mat3 U, Vec3 b) {
    Vec3 x;
    x.z = b.z / U.m[2][2];
    x.y = (b.y - U.m[2][1] * x.z) / U.m[1][1];
    x.x = (b.x - U.m[1][0] * x.y - U.m[2][0] * x.z) / U.m[0][0];
    return x;
}

static inline Mat3 mat3_exp(Mat3 A, int terms) {
    Mat3 result = mat3_identity();
    Mat3 power_A = mat3_identity();
    float factorial = 1.0f;
    for (int n = 1; n < terms; ++n) {
        factorial *= (float)n;
        power_A = mat3_mul(power_A, A);
        Mat3 term = mat3_scalar_mul(power_A, 1.0f / factorial);
        result = mat3_add(result, term);
    }
    return result;
}

/// @brief Multiplies two 4x4 matrices using SIMD.
static inline Mat4 mat4_mul(Mat4 a, Mat4 b) {
    Mat4 result;
    for (int i = 0; i < 4; i++) {
        // We are calculating Column i of the result.
        // Res_Col_i = A * B_Col_i
        // This is a Matrix * Vector operation.
        // B_Col_i is a vector (b.cols[i]).

        simd_vec_t b_col = b.cols[i];

        // Splat components of B's column
        simd_vec_t x = simd_splat_x(b_col);
        simd_vec_t y = simd_splat_y(b_col);
        simd_vec_t z = simd_splat_z(b_col);
        simd_vec_t w = simd_splat_w(b_col);

        // Linear combination of A's columns
        // Res = x*A0 + y*A1 + z*A2 + w*A3
        simd_vec_t r = simd_mul(a.cols[0], x);
        r = simd_add(r, simd_mul(a.cols[1], y));
        r = simd_add(r, simd_mul(a.cols[2], z));
        r = simd_add(r, simd_mul(a.cols[3], w));

        result.cols[i] = r;
    }
    return result;
}

// ======================
// Matrix-Vector Operations
// ======================

static inline Vec3 mat3_mul_vec3(Mat3 m, Vec3 v) {
    simd_vec_t vx = simd_set1(v.x);
    simd_vec_t vy = simd_set1(v.y);
    simd_vec_t vz = simd_set1(v.z);

    // Load columns. We must be careful about memory boundaries.
    // Col 0: OK (4 floats)
    simd_vec_t c0 = simd_load(&m.m[0][0]);
    // Col 1: OK (4 floats)
    simd_vec_t c1 = simd_load(&m.m[1][0]);
    // Col 2: OK (4 floats)
    simd_vec_t c2 = simd_load(&m.m[2][0]);

    // Sum: c0*x + c1*y + c2*z
    simd_vec_t res = simd_mul(c0, vx);
    res = simd_add(res, simd_mul(c1, vy));
    res = simd_add(res, simd_mul(c2, vz));

    // We have {Rx, Ry, Rz, Garbage}
    Vec3 out;
    simd_vec_t temp = res;  // Holder
    // To extract, we can store or use simd_get functions if available
    float f[4];
    simd_store(f, temp);
    out.x = f[0];
    out.y = f[1];
    out.z = f[2];
    return out;
}

static inline Vec4 mat4_mul_vec4(Mat4 m, Vec4 v) {
    // Result = v.x * Col0 + v.y * Col1 + v.z * Col2 + v.w * Col3
    simd_vec_t vec = simd_load((const float*)&v);

    simd_vec_t x = simd_splat_x(vec);
    simd_vec_t y = simd_splat_y(vec);
    simd_vec_t z = simd_splat_z(vec);
    simd_vec_t w = simd_splat_w(vec);

    simd_vec_t res = simd_mul(m.cols[0], x);
    res = simd_add(res, simd_mul(m.cols[1], y));
    res = simd_add(res, simd_mul(m.cols[2], z));
    res = simd_add(res, simd_mul(m.cols[3], w));

    Vec4 out;
    simd_store((float*)&out, res);
    return out;
}

static inline Mat4 mat4_div(Mat4 a, float b) {
    Mat4 result;
    simd_vec_t div = simd_set1(b);
    result.cols[0] = simd_div(a.cols[0], div);
    result.cols[1] = simd_div(a.cols[1], div);
    result.cols[2] = simd_div(a.cols[2], div);
    result.cols[3] = simd_div(a.cols[3], div);
    return result;
}

// ======================
// Transformation Matrices
// ======================

static inline Mat4 mat4_translate(Vec3 translation) {
    Mat4 m = mat4_identity();
    m.cols[3] = simd_set(translation.x, translation.y, translation.z, 1.0f);
    return m;
}

static inline Mat4 mat4_scale(Vec3 scale) {
    Mat4 m = mat4_identity();
    m.cols[0] = simd_mul(m.cols[0], simd_set1(scale.x));
    m.cols[1] = simd_mul(m.cols[1], simd_set1(scale.y));
    m.cols[2] = simd_mul(m.cols[2], simd_set1(scale.z));
    return m;
}

static inline Mat4 mat4_rotate_x(float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    Mat4 m = mat4_identity();
    m.cols[1] = simd_set(0.0f, c, s, 0.0f);
    m.cols[2] = simd_set(0.0f, -s, c, 0.0f);
    return m;
}

static inline Mat4 mat4_rotate_y(float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    Mat4 m = mat4_identity();
    m.cols[0] = simd_set(c, 0.0f, -s, 0.0f);
    m.cols[2] = simd_set(s, 0.0f, c, 0.0f);
    return m;
}

static inline Mat4 mat4_rotate_z(float angle) {
    float c = cosf(angle);
    float s = sinf(angle);
    Mat4 m = mat4_identity();
    m.cols[0] = simd_set(c, s, 0.0f, 0.0f);
    m.cols[1] = simd_set(-s, c, 0.0f, 0.0f);
    return m;
}

static inline Mat4 mat4_rotate(Vec3 axis, float angle) {
    SimdVec3 a = vec3_normalize(vec3_load(axis));
    float c = cosf(angle);
    float s = sinf(angle);
    float t = 1.0f - c;

    Mat4 m = mat4_identity();

    // Diagonal (Row == Col, so no swap needed)
    m.m[0][0] = t * a.x * a.x + c;
    m.m[1][1] = t * a.y * a.y + c;
    m.m[2][2] = t * a.z * a.z + c;

    // Off-diagonals
    // Standard Math: Row 0, Col 1 => t*x*y - s*z
    // Storage: m[1][0]
    m.m[1][0] = t * a.x * a.y - s * a.z;

    // Standard Math: Row 0, Col 2 => t*x*z + s*y
    // Storage: m[2][0]
    m.m[2][0] = t * a.x * a.z + s * a.y;

    // Standard Math: Row 1, Col 0 => t*x*y + s*z
    // Storage: m[0][1]
    m.m[0][1] = t * a.x * a.y + s * a.z;

    // Standard Math: Row 1, Col 2 => t*y*z - s*x
    // Storage: m[2][1]
    m.m[2][1] = t * a.y * a.z - s * a.x;

    // Standard Math: Row 2, Col 0 => t*x*z - s*y
    // Storage: m[0][2]
    m.m[0][2] = t * a.x * a.z - s * a.y;

    // Standard Math: Row 2, Col 1 => t*y*z + s*x
    // Storage: m[1][2]
    m.m[1][2] = t * a.y * a.z + s * a.x;

    return m;
}

// ======================
// Matrix Inversion
// ======================

static inline Mat4 mat4_transpose(Mat4 m) {
    // Requires simd_transpose4 macro in simd.h
    simd_transpose4(m.cols[0], m.cols[1], m.cols[2], m.cols[3]);
    return m;
}

/* =========================================================
   Determinant & Inverse (Fixed)
   ========================================================= */

static inline float mat4_determinant(Mat4 m) {
    // Column 0 elements
    float m00 = m.m[0][0], m10 = m.m[0][1], m20 = m.m[0][2], m30 = m.m[0][3];
    // Column 1 elements
    float m01 = m.m[1][0], m11 = m.m[1][1], m21 = m.m[1][2], m31 = m.m[1][3];
    // Column 2 elements
    float m02 = m.m[2][0], m12 = m.m[2][1], m22 = m.m[2][2], m32 = m.m[2][3];
    // Column 3 elements
    float m03 = m.m[3][0], m13 = m.m[3][1], m23 = m.m[3][2], m33 = m.m[3][3];

    // Compute determinant using expansion along the first column
    // This is verbose but allows the compiler to optimize the arithmetic tree

    float det = m00 * (m11 * (m22 * m33 - m32 * m23) - m21 * (m12 * m33 - m32 * m13) + m31 * (m12 * m23 - m22 * m13)) -
                m10 * (m01 * (m22 * m33 - m32 * m23) - m21 * (m02 * m33 - m32 * m03) + m31 * (m02 * m23 - m22 * m03)) +
                m20 * (m01 * (m12 * m33 - m32 * m13) - m11 * (m02 * m33 - m32 * m03) + m31 * (m02 * m13 - m12 * m03)) -
                m30 * (m01 * (m12 * m23 - m22 * m13) - m11 * (m02 * m23 - m22 * m03) + m21 * (m02 * m13 - m12 * m03));

    return det;
}

static inline Mat4 mat4_inverse(Mat4 m) {
    // 1. Load matrix elements (Column-Major access: m[col][row])
    float m00 = m.m[0][0], m01 = m.m[1][0], m02 = m.m[2][0], m03 = m.m[3][0];
    float m10 = m.m[0][1], m11 = m.m[1][1], m12 = m.m[2][1], m13 = m.m[3][1];
    float m20 = m.m[0][2], m21 = m.m[1][2], m22 = m.m[2][2], m23 = m.m[3][2];
    float m30 = m.m[0][3], m31 = m.m[1][3], m32 = m.m[2][3], m33 = m.m[3][3];

    // 2. Compute 2x2 Sub-determinants (Factors)
    //    Pairs for Rows 2,3
    float Fac0 = m22 * m33 - m32 * m23;
    float Fac1 = m21 * m33 - m31 * m23;
    float Fac2 = m21 * m32 - m31 * m22;
    float Fac3 = m20 * m33 - m30 * m23;
    float Fac4 = m20 * m32 - m30 * m22;
    float Fac5 = m20 * m31 - m30 * m21;
    //    Pairs for Rows 0,1
    float Fac6 = m02 * m13 - m12 * m03;
    float Fac7 = m01 * m13 - m11 * m03;
    float Fac8 = m01 * m12 - m11 * m02;
    float Fac9 = m00 * m13 - m10 * m03;
    float Fac10 = m00 * m12 - m10 * m02;
    float Fac11 = m00 * m11 - m10 * m01;

    // 3. Compute Adjugate Matrix Columns (Transpose of Cofactors)

    // Inverse Column 0
    simd_vec_t col0 = simd_set((m11 * Fac0 - m12 * Fac1 + m13 * Fac2), -(m10 * Fac0 - m12 * Fac3 + m13 * Fac4),
                               (m10 * Fac1 - m11 * Fac3 + m13 * Fac5), -(m10 * Fac2 - m11 * Fac4 + m12 * Fac5));

    // Inverse Column 1
    simd_vec_t col1 = simd_set(-(m01 * Fac0 - m02 * Fac1 + m03 * Fac2), (m00 * Fac0 - m02 * Fac3 + m03 * Fac4),
                               -(m00 * Fac1 - m01 * Fac3 + m03 * Fac5), (m00 * Fac2 - m01 * Fac4 + m02 * Fac5));

    // Inverse Column 2
    simd_vec_t col2 = simd_set((m31 * Fac6 - m32 * Fac7 + m33 * Fac8), -(m30 * Fac6 - m32 * Fac9 + m33 * Fac10),
                               (m30 * Fac7 - m31 * Fac9 + m33 * Fac11), -(m30 * Fac8 - m31 * Fac10 + m32 * Fac11));

    // Inverse Column 3
    simd_vec_t col3 = simd_set(-(m21 * Fac6 - m22 * Fac7 + m23 * Fac8), (m20 * Fac6 - m22 * Fac9 + m23 * Fac10),
                               -(m20 * Fac7 - m21 * Fac9 + m23 * Fac11), (m20 * Fac8 - m21 * Fac10 + m22 * Fac11));

    // 4. Calculate Determinant
    //    Dot product of first column of inputs with first column of adjugate
    //    Det = m00*Adj00 + m10*Adj10 + m20*Adj20 + m30*Adj30
    simd_vec_t input_col0 = simd_set(m00, m10, m20, m30);
    float det = simd_dot4(input_col0, col0);

    // 5. Check Singularity
    if (fabsf(det) < 1e-8f) {
        return mat4_identity();
    }

    // 6. Scale by 1/Det
    simd_vec_t inv_det_vec = simd_set1(1.0f / det);

    Mat4 inv;
    inv.cols[0] = simd_mul(col0, inv_det_vec);
    inv.cols[1] = simd_mul(col1, inv_det_vec);
    inv.cols[2] = simd_mul(col2, inv_det_vec);
    inv.cols[3] = simd_mul(col3, inv_det_vec);

    return inv;
}

// ======================
// Projection Matrices
// ======================

static inline Mat4 mat4_ortho(float left, float right, float bottom, float top, float near, float far) {
    Mat4 m = mat4_identity();
    // Diagonals
    m.cols[0] = simd_set(2.0f / (right - left), 0, 0, 0);
    m.cols[1] = simd_set(0, 2.0f / (top - bottom), 0, 0);
    m.cols[2] = simd_set(0, 0, -2.0f / (far - near), 0);

    // Last column
    m.cols[3] = simd_set(-(right + left) / (right - left), -(top + bottom) / (top - bottom),
                         -(far + near) / (far - near), 1.0f);
    return m;
}

static inline Mat4 mat4_perspective(float fov_radians, float aspect, float near, float far) {
    float tan_half_fov = tanf(fov_radians / 2.0f);
    Mat4 m;
    m.cols[0] = simd_set(1.0f / (aspect * tan_half_fov), 0, 0, 0);
    m.cols[1] = simd_set(0, 1.0f / tan_half_fov, 0, 0);
    m.cols[2] = simd_set(0, 0, -(far + near) / (far - near), -1.0f);
    m.cols[3] = simd_set(0, 0, -(2.0f * far * near) / (far - near), 0.0f);
    return m;
}

static inline Mat4 mat4_look_at(SimdVec3 eye, SimdVec3 target, SimdVec3 up) {
    SimdVec3 z = vec3_normalize(vec3_sub(eye, target));
    SimdVec3 x = vec3_normalize(vec3_cross(up, z));
    SimdVec3 y = vec3_cross(z, x);

    Mat4 view;
    view.cols[0] = simd_set(x.x, y.x, z.x, 0.0f);  // Col 0 (Row 0 of rotation)
    view.cols[1] = simd_set(x.y, y.y, z.y, 0.0f);  // Col 1
    view.cols[2] = simd_set(x.z, y.z, z.z, 0.0f);  // Col 2

    // Dot products for translation
    view.cols[3] = simd_set(-vec3_dot(x, eye), -vec3_dot(y, eye), -vec3_dot(z, eye), 1.0f);
    return view;
}

static inline Mat4 mat4_add(Mat4 a, Mat4 b) {
    Mat4 res;
    res.cols[0] = simd_add(a.cols[0], b.cols[0]);
    res.cols[1] = simd_add(a.cols[1], b.cols[1]);
    res.cols[2] = simd_add(a.cols[2], b.cols[2]);
    res.cols[3] = simd_add(a.cols[3], b.cols[3]);
    return res;
}

static inline Mat4 mat4_sub(Mat4 a, Mat4 b) {
    Mat4 res;
    res.cols[0] = simd_sub(a.cols[0], b.cols[0]);
    res.cols[1] = simd_sub(a.cols[1], b.cols[1]);
    res.cols[2] = simd_sub(a.cols[2], b.cols[2]);
    res.cols[3] = simd_sub(a.cols[3], b.cols[3]);
    return res;
}

static inline Mat4 mat4_scalar_mul(Mat4 a, float s) {
    Mat4 res;
    simd_vec_t v = simd_set1(s);
    res.cols[0] = simd_mul(a.cols[0], v);
    res.cols[1] = simd_mul(a.cols[1], v);
    res.cols[2] = simd_mul(a.cols[2], v);
    res.cols[3] = simd_mul(a.cols[3], v);
    return res;
}

/* ==================================================
   Graphics Extensions: Mat3 utilities
   ================================================== */

/**
 * @brief Transposes a 3x3 matrix.
 */
static inline Mat3 mat3_transpose(Mat3 m) {
    Mat3 r;
    for (int c = 0; c < 3; c++) {
        for (int row = 0; row < 3; row++) {
            r.m[c][row] = m.m[row][c];
        }
    }
    return r;
}

/**
 * @brief Inverts a 3x3 matrix using the adjugate method.
 *
 * @return The inverse, or the identity matrix if the input is singular
 *         (|det| < 1e-8), matching mat4_inverse()'s fallback behavior.
 */
static inline Mat3 mat3_inverse(Mat3 m) {
    float m00 = m.m[0][0], m01 = m.m[1][0], m02 = m.m[2][0];
    float m10 = m.m[0][1], m11 = m.m[1][1], m12 = m.m[2][1];
    float m20 = m.m[0][2], m21 = m.m[1][2], m22 = m.m[2][2];

    // Cofactors of the first column and row pieces (adjugate columns)
    float c00 = m11 * m22 - m12 * m21;
    float c01 = m02 * m21 - m01 * m22;
    float c02 = m01 * m12 - m02 * m11;

    float det = m00 * c00 + m10 * c01 + m20 * c02;
    if (fabsf(det) < 1e-8f) {
        return mat3_identity();
    }
    float inv_det = 1.0f / det;

    Mat3 inv;
    // Adjugate / det; adjugate is the transpose of the cofactor matrix.
    inv.m[0][0] = c00 * inv_det;
    inv.m[1][0] = c01 * inv_det;
    inv.m[2][0] = c02 * inv_det;

    inv.m[0][1] = (m12 * m20 - m10 * m22) * inv_det;
    inv.m[1][1] = (m00 * m22 - m02 * m20) * inv_det;
    inv.m[2][1] = (m02 * m10 - m00 * m12) * inv_det;

    inv.m[0][2] = (m10 * m21 - m11 * m20) * inv_det;
    inv.m[1][2] = (m01 * m20 - m00 * m21) * inv_det;
    inv.m[2][2] = (m00 * m11 - m01 * m10) * inv_det;
    return inv;
}

/**
 * @brief Computes the normal matrix for a model transform.
 *
 * Normals must be transformed by the inverse-transpose of the model
 * matrix's upper-left 3x3 to remain correct under non-uniform scaling.
 * Extracts that 3x3, inverts it, and transposes it.
 *
 * @param model The model (world) transform.
 * @return Mat3 Use as: normal_world = mat3_mul_vec3(normal_matrix, normal_local).
 */
static inline Mat3 mat3_normal_matrix(Mat4 model) {
    Mat3 upper;
    for (int c = 0; c < 3; c++) {
        for (int r = 0; r < 3; r++) {
            upper.m[c][r] = model.m[c][r];
        }
    }
    return mat3_transpose(mat3_inverse(upper));
}

/* ==================================================
   Graphics Extensions: point/direction transforms & picking
   ================================================== */

/**
 * @brief Transforms a 3D point by a 4x4 matrix (w = 1, perspective-divided).
 *
 * Equivalent to mat4_mul_vec4(m, vec4_from_point(p)) followed by division
 * by w. This is the correct way to transform vertex positions through an
 * MVP matrix when you want world/object-space results rather than clip space.
 *
 * @warning If w ends up 0 or near-zero (point at/behind the camera plane),
 *          the result is undefined. Clip before dividing in production paths.
 */
static inline Vec3 mat4_transform_point(Mat4 m, Vec3 p) {
    Vec4 h = mat4_mul_vec4(m, vec4_from_point(p));
    float inv_w = 1.0f / h.w;
    return (Vec3){h.x * inv_w, h.y * inv_w, h.z * inv_w};
}

/**
 * @brief Transforms a 3D direction by a 4x4 matrix (w = 0, no translation).
 *
 * Uses only the upper-left 3x3 of the matrix, so translations are ignored.
 * Correct for directions/tangents; for surface normals under non-uniform
 * scale use mat3_normal_matrix() instead.
 */
static inline Vec3 mat4_transform_direction(Mat4 m, Vec3 d) {
    Vec4 h = mat4_mul_vec4(m, vec4_from_direction(d));
    return (Vec3){h.x, h.y, h.z};
}

/**
 * @brief Creates a centered 2D orthographic projection over pixel coordinates.
 *
 * Maps (0,0) to the bottom-left and (width,height) to the top-right of NDC,
 * with z in [-1, 1]. Typical use: UI/screen-space rendering where geometry
 * is specified directly in window pixels.
 */
static inline Mat4 mat4_ortho_2d(float width, float height) {
    return mat4_ortho(0.0f, width, 0.0f, height, -1.0f, 1.0f);
}

/**
 * @brief Perspective projection with an infinite far plane (OpenGL convention).
 *
 * Same [-1, 1] depth convention as mat4_perspective(), but the far plane is
 * pushed to infinity, which maximizes depth-buffer precision. Pair with a
 * reversed-Z depth test for best results.
 *
 * @param fov_radians Vertical field of view.
 * @param aspect     Width / height of the viewport.
 * @param near       Distance to the near plane (> 0).
 */
static inline Mat4 mat4_infinite_perspective(float fov_radians, float aspect, float near) {
    float f = 1.0f / tanf(fov_radians / 2.0f);
    Mat4 m;
    m.cols[0] = simd_set(f / aspect, 0.0f, 0.0f, 0.0f);
    m.cols[1] = simd_set(0.0f, f, 0.0f, 0.0f);
    m.cols[2] = simd_set(0.0f, 0.0f, -1.0f, -1.0f);
    m.cols[3] = simd_set(0.0f, 0.0f, -2.0f * near, 0.0f);
    return m;
}

/**
 * @brief Converts window/pixel coordinates to normalized device coordinates.
 *
 * Follows the common top-left-origin screen convention: (0,0) maps to
 * NDC (-1, 1). Depth is passed through unchanged, so pick your own z
 * convention (typically -1..1 for OpenGL-style projections).
 *
 * @param sx Horizontal position in pixels.
 * @param sy Vertical position in pixels (top-left origin).
 * @param width Viewport width in pixels.
 * @param height Viewport height in pixels.
 * @return Vec3 NDC position (z copied from input).
 */
static inline Vec3 screen_to_ndc(float sx, float sy, float z, float width, float height) {
    float x = 2.0f * sx / width - 1.0f;
    float y = 1.0f - 2.0f * sy / height;
    return (Vec3){x, y, z};
}

/**
 * @brief Unprojects an NDC coordinate back into world space.
 *
 * Applies inverse_view_proj as a homogeneous transform and divides by w.
 * For ray picking: unproject at z = -1 (near plane) and z = 1 (far plane)
 * and take the normalized difference as the ray direction.
 *
 * @param inverse_view_proj Precomputed inverse of (projection * view).
 * @param ndc Position in normalized device coordinates.
 * @return Vec3 World-space position.
 */
static inline Vec3 mat4_unproject(Mat4 inverse_view_proj, Vec3 ndc) {
    Vec4 world = mat4_mul_vec4(inverse_view_proj, (Vec4){ndc.x, ndc.y, ndc.z, 1.0f});
    if (fabsf(world.w) < 1e-10f) {
        return (Vec3){0};
    }
    float inv_w = 1.0f / world.w;
    return (Vec3){world.x * inv_w, world.y * inv_w, world.z * inv_w};
}

/* ==================================================
   Quaternions
   ================================================== */

/**
 * @struct Quat
 * @brief Unit quaternion representing a 3D rotation.
 *
 * Storage layout matches Vec4/SimdVec4 component-for-component, so a
 * quaternion can be reinterpreted as either without conversion cost.
 * Multiplication order follows the standard q1 * q2 == "apply q2 first":
 * mat4_from_quat(quat_mul(a, b)) == mat4_mul(mat4_from_quat(a), mat4_from_quat(b)).
 */
typedef struct ALIGN(16) Quat {
    union {
        struct {
            float x;  ///< Imaginary X component
            float y;  ///< Imaginary Y component
            float z;  ///< Imaginary Z component
            float w;  ///< Real (scalar) component
        };
        Vec4 as_vec4;  ///< Reinterpretation for SIMD loads
    };
} Quat;

/** @brief Identity rotation (no rotation). */
static inline Quat quat_identity(void) { return (Quat){.x = 0.0f, .y = 0.0f, .z = 0.0f, .w = 1.0f}; }

/**
 * @brief Creates a rotation quaternion around an arbitrary axis.
 *
 * @param axis Rotation axis (need not be normalized; it is normalized here).
 * @param angle Rotation angle in radians (right-hand rule).
 * @return Unit rotation quaternion.
 */
static inline Quat quat_from_axis_angle(Vec3 axis, float angle) {
    SimdVec3 a = vec3_normalize(vec3_load(axis));
    float s = sinf(angle * 0.5f);
    return (Quat){.x = a.x * s, .y = a.y * s, .z = a.z * s, .w = cosf(angle * 0.5f)};
}

/**
 * @brief Creates a rotation from Euler angles applied in X -> Y -> Z order.
 *
 * Equivalent to Rz(yaw) * Ry(pitch) * Rx(roll) as matrices. All angles in
 * radians. Convenient for cameras and editors, but avoid accumulating many
 * small euler rotations — compose quaternions instead.
 *
 * @param roll  Rotation about X.
 * @param pitch Rotation about Y.
 * @param yaw   Rotation about Z.
 */
static inline Quat quat_from_euler(float roll, float pitch, float yaw) {
    float cr = cosf(roll * 0.5f), sr = sinf(roll * 0.5f);
    float cp = cosf(pitch * 0.5f), sp = sinf(pitch * 0.5f);
    float cy = cosf(yaw * 0.5f), sy = sinf(yaw * 0.5f);

    return (Quat){
        .x = sr * cp * cy - cr * sp * sy,
        .y = cr * sp * cy + sr * cp * sy,
        .z = cr * cp * sy - sr * sp * cy,
        .w = cr * cp * cy + sr * sp * sy,
    };
}

/** @brief Component-wise dot product (cosine of half the relative angle for units). */
static inline float quat_dot(Quat a, Quat b) { return a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w; }

/** @brief Squared length of the quaternion. */
static inline float quat_length_sq(Quat q) { return quat_dot(q, q); }

/** @brief Length of the quaternion (1.0 for unit rotations). */
static inline float quat_length(Quat q) { return sqrtf(quat_length_sq(q)); }

/**
 * @brief Normalizes to a unit quaternion.
 *
 * @warning Returns the identity if the input is degenerate (all zeros),
 *          unlike the vector normalize functions which are undefined then.
 */
static inline Quat quat_normalize(Quat q) {
    float len = quat_length(q);
    if (len < 1e-12f) {
        return quat_identity();
    }
    float inv = 1.0f / len;
    return (Quat){.x = q.x * inv, .y = q.y * inv, .z = q.z * inv, .w = q.w * inv};
}

/** @brief Conjugate (inverse for unit quaternions): negates the imaginary part. */
static inline Quat quat_conjugate(Quat q) { return (Quat){.x = -q.x, .y = -q.y, .z = -q.z, .w = q.w}; }

/**
 * @brief Hamilton product of two quaternions.
 *
 * Composes rotations: quat_mul(q1, q2) applies q2 first, then q1.
 */
static inline Quat quat_mul(Quat a, Quat b) {
    return (Quat){
        .x = a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
        .y = a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x,
        .z = a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w,
        .w = a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z,
    };
}

/**
 * @brief Rotates a vector by a unit quaternion.
 *
 * Uses the optimized form t = 2*(q.xyz x v); v' = v + q.w*t + (q.xyz x t)
 * instead of building the full rotation matrix.
 *
 * @param q Unit rotation quaternion.
 * @param v Vector to rotate.
 * @return Rotated vector.
 */
static inline SimdVec3 quat_rotate_vec3(Quat q, SimdVec3 v) {
    SimdVec3 qc = {{q.x, q.y, q.z, 0.0f}};
    SimdVec3 t = vec3_mul(vec3_cross(qc, v), 2.0f);
    return vec3_add(vec3_add(v, vec3_mul(t, q.w)), vec3_cross(qc, t));
}

/**
 * @brief Normalized linear interpolation between two rotations.
 *
 * Faster than quat_slerp() but not constant angular velocity. Take the
 * shortest path automatically (b is negated when dot(a,b) < 0).
 */
static inline Quat quat_nlerp(Quat a, Quat b, float t) {
    if (quat_dot(a, b) < 0.0f) {
        b = (Quat){.x = -b.x, .y = -b.y, .z = -b.z, .w = -b.w};
    }
    Quat r = (Quat){
        .x = a.x + (b.x - a.x) * t,
        .y = a.y + (b.y - a.y) * t,
        .z = a.z + (b.z - a.z) * t,
        .w = a.w + (b.w - a.w) * t,
    };
    return quat_normalize(r);
}

/**
 * @brief Spherical linear interpolation between two rotations.
 *
 * Constant angular velocity along the shortest arc. Falls back to
 * nlerp-style blending for nearly-parallel inputs where sin(theta) ~ 0.
 */
static inline Quat quat_slerp(Quat a, Quat b, float t) {
    float dot = quat_dot(a, b);

    // Shortest path: flip one representative if the hemispheres differ.
    if (dot < 0.0f) {
        dot = -dot;
        b = (Quat){.x = -b.x, .y = -b.y, .z = -b.z, .w = -b.w};
    }

    float k0, k1;
    if (dot > 0.9995f) {
        // Nearly identical: linear blend avoids division by tiny sin(theta).
        k0 = 1.0f - t;
        k1 = t;
    } else {
        float theta = acosf(dot);
        float sin_theta = sinf(theta);
        k0 = sinf((1.0f - t) * theta) / sin_theta;
        k1 = sinf(t * theta) / sin_theta;
    }

    return quat_normalize((Quat){
        .x = a.x * k0 + b.x * k1,
        .y = a.y * k0 + b.y * k1,
        .z = a.z * k0 + b.z * k1,
        .w = a.w * k0 + b.w * k1,
    });
}

/**
 * @brief Converts a unit rotation quaternion to a 4x4 rotation matrix.
 */
static inline Mat4 mat4_from_quat(Quat q) {
    float xx = q.x * q.x, yy = q.y * q.y, zz = q.z * q.z;
    float xy = q.x * q.y, xz = q.x * q.z, yz = q.y * q.z;
    float wx = q.w * q.x, wy = q.w * q.y, wz = q.w * q.z;

    Mat4 m = mat4_identity();
    // Column-major: m[col][row]
    m.m[0][0] = 1.0f - 2.0f * (yy + zz);
    m.m[0][1] = 2.0f * (xy + wz);
    m.m[0][2] = 2.0f * (xz - wy);

    m.m[1][0] = 2.0f * (xy - wz);
    m.m[1][1] = 1.0f - 2.0f * (xx + zz);
    m.m[1][2] = 2.0f * (yz + wx);

    m.m[2][0] = 2.0f * (xz + wy);
    m.m[2][1] = 2.0f * (yz - wx);
    m.m[2][2] = 1.0f - 2.0f * (xx + yy);
    return m;
}

/**
 * @brief Converts a unit rotation quaternion to a 3x3 rotation matrix.
 */
static inline Mat3 mat3_from_quat(Quat q) {
    Mat4 m = mat4_from_quat(q);
    Mat3 r;
    for (int c = 0; c < 3; c++) {
        for (int row = 0; row < 3; row++) {
            r.m[c][row] = m.m[c][row];
        }
    }
    return r;
}

/**
 * @brief Extracts a rotation quaternion from a pure rotation matrix.
 *
 * Uses Shepperd's method (largest-trace pivot) for numerical stability.
 * Assumes the upper-left 3x3 contains only rotation + uniform positive
 * scale; decompose scaled matrices with mat4_decompose() first.
 */
static inline Quat quat_from_mat4(Mat4 m) {
    // Storage note: m[col][row]. Standard notation R<row><col> therefore maps
    // to m.m[<col>][<row>] — e.g., R21 == m.m[1][2].
    float trace = m.m[0][0] + m.m[1][1] + m.m[2][2];
    Quat q;

    if (trace > 0.0f) {
        float s = sqrtf(trace + 1.0f) * 2.0f;  // s = 4w
        q.w = 0.25f * s;
        q.x = (m.m[1][2] - m.m[2][1]) / s;  // R21 - R12
        q.y = (m.m[2][0] - m.m[0][2]) / s;  // R02 - R20
        q.z = (m.m[0][1] - m.m[1][0]) / s;  // R10 - R01
    } else if (m.m[0][0] > m.m[1][1] && m.m[0][0] > m.m[2][2]) {
        float s = sqrtf(1.0f + m.m[0][0] - m.m[1][1] - m.m[2][2]) * 2.0f;  // s = 4x
        q.w = (m.m[1][2] - m.m[2][1]) / s;
        q.x = 0.25f * s;
        q.y = (m.m[1][0] + m.m[0][1]) / s;  // R01 + R10
        q.z = (m.m[2][0] + m.m[0][2]) / s;  // R02 + R20
    } else if (m.m[1][1] > m.m[2][2]) {
        float s = sqrtf(1.0f + m.m[1][1] - m.m[0][0] - m.m[2][2]) * 2.0f;  // s = 4y
        q.w = (m.m[2][0] - m.m[0][2]) / s;
        q.x = (m.m[1][0] + m.m[0][1]) / s;
        q.y = 0.25f * s;
        q.z = (m.m[2][1] + m.m[1][2]) / s;  // R12 + R21
    } else {
        float s = sqrtf(1.0f + m.m[2][2] - m.m[0][0] - m.m[1][1]) * 2.0f;  // s = 4z
        q.w = (m.m[0][1] - m.m[1][0]) / s;
        q.x = (m.m[2][0] + m.m[0][2]) / s;
        q.y = (m.m[2][1] + m.m[1][2]) / s;
        q.z = 0.25f * s;
    }
    return q;
}

/**
 * @brief Builds a model matrix from translation, rotation, and scale (TRS).
 *
 * Computes T * R * S in one pass, equivalent to
 * mat4_mul(mat4_translate(t), mat4_mul(mat4_from_quat(r), mat4_scale(s)))
 * but cheaper and more convenient. This is the standard way to place an
 * object in a scene graph.
 *
 * @param translation World position.
 * @param rotation    Unit rotation quaternion.
 * @param scale       Non-uniform scale factors.
 */
static inline Mat4 mat4_compose(Vec3 translation, Quat rotation, Vec3 scale) {
    float xx = rotation.x * rotation.x, yy = rotation.y * rotation.y, zz = rotation.z * rotation.z;
    float xy = rotation.x * rotation.y, xz = rotation.x * rotation.z, yz = rotation.y * rotation.z;
    float wx = rotation.w * rotation.x, wy = rotation.w * rotation.y, wz = rotation.w * rotation.z;

    Mat4 m = mat4_identity();
    // Scaled rotation basis vectors as columns.
    m.m[0][0] = (1.0f - 2.0f * (yy + zz)) * scale.x;
    m.m[0][1] = (2.0f * (xy + wz)) * scale.x;
    m.m[0][2] = (2.0f * (xz - wy)) * scale.x;

    m.m[1][0] = (2.0f * (xy - wz)) * scale.y;
    m.m[1][1] = (1.0f - 2.0f * (xx + zz)) * scale.y;
    m.m[1][2] = (2.0f * (yz + wx)) * scale.y;

    m.m[2][0] = (2.0f * (xz + wy)) * scale.z;
    m.m[2][1] = (2.0f * (yz - wx)) * scale.z;
    m.m[2][2] = (1.0f - 2.0f * (xx + yy)) * scale.z;

    m.m[3][0] = translation.x;
    m.m[3][1] = translation.y;
    m.m[3][2] = translation.z;
    return m;
}

#ifdef __cplusplus
}
#endif

#endif  // MATRIX_H
