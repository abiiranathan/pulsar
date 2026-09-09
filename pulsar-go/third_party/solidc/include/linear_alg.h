/**
 * @file linear_alg.h
 * @brief Linear algebra operations and utilities.
 */

#ifndef LINEAR_ALG_H
#define LINEAR_ALG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "matrix.h"
#include "vec.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Orthonormal basis consisting of three mutually perpendicular unit vectors.
 * Forms a right-handed coordinate system.
 */
typedef struct {
    Vec3 v0; /**< Right vector. */
    Vec3 v1; /**< Up vector. */
    Vec3 v2; /**< Forward vector. */
} OrthonormalBasis;

/**
 * Constructs an orthonormal basis from two input vectors using Gram-Schmidt orthogonalization.
 */
static inline OrthonormalBasis orthonormalize(Vec3 v0, Vec3 v1) {
    SimdVec3 sv0 = vec3_load(v0);
    SimdVec3 sv1 = vec3_load(v1);

    sv0 = vec3_normalize(sv0);

    float dot = vec3_dot(sv0, sv1);
    sv1 = vec3_sub(sv1, vec3_mul(sv0, dot));
    sv1 = vec3_normalize(sv1);

    SimdVec3 sv2 = vec3_cross(sv0, sv1);

    return (OrthonormalBasis){vec3_store(sv0), vec3_store(sv1), vec3_store(sv2)};
}

/**
 * Result of eigenvalue decomposition for a 3x3 matrix.
 */
typedef struct {
    Vec3 eigenvalues;  /**< Eigenvalues (x, y, z). */
    Mat3 eigenvectors; /**< Eigenvectors stored as columns. */
} EigenDecomposition;

/**
 * Computes eigenvalues/vectors of a symmetric 3x3 matrix using Jacobi iteration.
 */
static inline EigenDecomposition mat3_eigen_symmetric(Mat3 A) {
    EigenDecomposition result;
    Mat3 V = mat3_identity();

    const int MAX_ITERS = 32;
    const float EPSILON = 1e-10f;

    for (int iter = 0; iter < MAX_ITERS; ++iter) {
        int p = 0, q = 1;
        float max = fabsf(A.m[0][1]);

        if (fabsf(A.m[0][2]) > max) {
            p = 0;
            q = 2;
            max = fabsf(A.m[0][2]);
        }
        if (fabsf(A.m[1][2]) > max) {
            p = 1;
            q = 2;
            max = fabsf(A.m[1][2]);
        }

        if (max < EPSILON) break;

        float app = A.m[p][p];
        float aqq = A.m[q][q];
        float apq = A.m[p][q];

        float phi = 0.5f * atanf((2.0f * apq) / (aqq - app + 1e-20f));
        float c = cosf(phi);
        float s = sinf(phi);

        for (int r = 0; r < 3; ++r) {
            float arp = A.m[r][p];
            float arq = A.m[r][q];
            A.m[r][p] = c * arp - s * arq;
            A.m[r][q] = s * arp + c * arq;
        }

        for (int r = 0; r < 3; ++r) {
            float arp = A.m[p][r];
            float arq = A.m[q][r];
            A.m[p][r] = c * arp - s * arq;
            A.m[q][r] = s * arp + c * arq;
        }

        A.m[p][p] = c * c * app - 2 * s * c * apq + s * s * aqq;
        A.m[q][q] = s * s * app + 2 * s * c * apq + c * c * aqq;
        A.m[p][q] = A.m[q][p] = 0.0f;

        for (int r = 0; r < 3; ++r) {
            float vrp = V.m[r][p];
            float vrq = V.m[r][q];
            V.m[r][p] = c * vrp - s * vrq;
            V.m[r][q] = s * vrp + c * vrq;
        }
    }

    result.eigenvalues = (Vec3){A.m[0][0], A.m[1][1], A.m[2][2]};
    result.eigenvectors = V;
    return result;
}

/**
 * Computes Singular Value Decomposition (SVD) of a 3x3 matrix.
 */
static inline void mat3_svd(Mat3 A, Mat3* U, Vec3* S, Mat3* V) {
    Mat3 ATA = {0};
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            ATA.m[i][j] = 0.0f;
            for (int k = 0; k < 3; ++k) {
                ATA.m[i][j] += A.m[i][k] * A.m[j][k];
            }
        }
    }

    EigenDecomposition ed = mat3_eigen_symmetric(ATA);
    *V = ed.eigenvectors;

    int order[3] = {0, 1, 2};
    float vals[3] = {ed.eigenvalues.x, ed.eigenvalues.y, ed.eigenvalues.z};

    for (int i = 0; i < 2; ++i) {
        for (int j = i + 1; j < 3; ++j) {
            if (vals[order[i]] < vals[order[j]]) {
                int tmp = order[i];
                order[i] = order[j];
                order[j] = tmp;
            }
        }
    }

    Vec3 sorted_eigen = {vals[order[0]], vals[order[1]], vals[order[2]]};

    Mat3 V_sorted = {0};
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 3; ++j) {
            V_sorted.m[i][j] = V->m[order[i]][j];
        }
    }
    *V = V_sorted;

    S->x = sqrtf(fmaxf(0.0f, sorted_eigen.x));
    S->y = sqrtf(fmaxf(0.0f, sorted_eigen.y));
    S->z = sqrtf(fmaxf(0.0f, sorted_eigen.z));

    SimdVec3 colA[3] = {vec3_load((Vec3){A.m[0][0], A.m[0][1], A.m[0][2]}),
                        vec3_load((Vec3){A.m[1][0], A.m[1][1], A.m[1][2]}),
                        vec3_load((Vec3){A.m[2][0], A.m[2][1], A.m[2][2]})};

    float* s_arr = (float*)S;
    for (int i = 0; i < 3; ++i) {
        float sigma = s_arr[i];
        if (sigma > 1e-6f) {
            Vec3 v_col = {V->m[i][0], V->m[i][1], V->m[i][2]};
            SimdVec3 Av =
                vec3_add(vec3_add(vec3_mul(colA[0], v_col.x), vec3_mul(colA[1], v_col.y)), vec3_mul(colA[2], v_col.z));
            SimdVec3 u_col = vec3_mul(Av, 1.0f / sigma);
            Vec3 res = vec3_store(u_col);
            U->m[i][0] = res.x;
            U->m[i][1] = res.y;
            U->m[i][2] = res.z;
        } else {
            U->m[i][0] = U->m[i][1] = U->m[i][2] = 0.0f;
        }
    }

    if (S->y > 1e-6f && S->z < 1e-6f) {
        SimdVec3 u0 = vec3_load((Vec3){U->m[0][0], U->m[0][1], U->m[0][2]});
        SimdVec3 u1 = vec3_load((Vec3){U->m[1][0], U->m[1][1], U->m[1][2]});
        SimdVec3 u2 = vec3_cross(u0, u1);
        Vec3 res = vec3_store(u2);
        U->m[2][0] = res.x;
        U->m[2][1] = res.y;
        U->m[2][2] = res.z;
    }

    if (mat3_determinant(*U) < 0.0f) {
        U->m[2][0] = -U->m[2][0];
        U->m[2][1] = -U->m[2][1];
        U->m[2][2] = -U->m[2][2];
    }
}

/**
 * Computes QR decomposition of a 4x4 matrix using SIMD Gram-Schmidt.
 * A = Q * R
 */
static inline void mat4_qr(Mat4 A, Mat4* Q, Mat4* R) {
    SimdVec4 v[4], q[4];
    for (int i = 0; i < 4; ++i) {
        v[i].v = A.cols[i];
    }

    for (int i = 0; i < 4; ++i) {
        q[i] = v[i];
        for (int j = 0; j < i; ++j) {
            float r = vec4_dot(q[j], v[i]);
            // Write to Upper Triangle (Col i, Row j)
            // Assuming Mat4 m[col][row], this is m[i][j]
            R->m[i][j] = r;
            q[i] = vec4_sub(q[i], vec4_mul(q[j], r));
        }

        float norm = vec4_length(q[i]);
        if (norm < 1e-6f) norm = 1e-6f;

        R->m[i][i] = norm;
        q[i] = vec4_mul(q[i], 1.0f / norm);

        // Zero the Lower Triangle (Col j, Row i where i > j)
        for (int j = 0; j < i; ++j) {
            R->m[j][i] = 0.0f;
        }
    }

    for (int i = 0; i < 4; ++i) {
        Q->cols[i] = q[i].v;
    }
}

/**
 * Computes the dominant eigenpair of a 4x4 matrix using SIMD power iteration.
 */
static inline void mat4_power_iteration(Mat4 A, Vec4* eigenvector, float* eigenvalue, int max_iter, float tol) {
    SimdVec4 v = vec4_load((Vec4){1.0f, 0.0f, 0.0f, 0.0f});
    SimdVec4 Av;
    float lambda_old = 0.0f;

    for (int iter = 0; iter < max_iter; ++iter) {
        Vec4 v_scalar = vec4_store(v);
        Vec4 Av_scalar = mat4_mul_vec4(A, v_scalar);
        Av = vec4_load(Av_scalar);

        *eigenvalue = vec4_dot(Av, v);
        Av = vec4_normalize(Av);

        if (fabsf(*eigenvalue - lambda_old) < tol) {
            break;
        }
        lambda_old = *eigenvalue;
        v = Av;
    }

    *eigenvector = vec4_store(v);
}

static inline float mat4_norm_frobenius(Mat4 A) {
    SimdVec4 c0 = {.v = A.cols[0]};
    SimdVec4 c1 = {.v = A.cols[1]};
    SimdVec4 c2 = {.v = A.cols[2]};
    SimdVec4 c3 = {.v = A.cols[3]};

    float sum = 0.0f;
    sum += vec4_dot(c0, c0);
    sum += vec4_dot(c1, c1);
    sum += vec4_dot(c2, c2);
    sum += vec4_dot(c3, c3);

    return sqrtf(sum);
}

static inline bool mat3_is_positive_definite(Mat3 A) {
    if (A.m[0][0] <= 0.0f) return false;
    float det2 = A.m[0][0] * A.m[1][1] - A.m[1][0] * A.m[0][1];
    if (det2 <= 0.0f) return false;
    if (mat3_determinant(A) <= 0.0f) return false;
    return true;
}

static inline float mat4_condition_number(Mat4 A) {
    float norm_A = mat4_norm_frobenius(A);
    Mat4 A_inv = mat4_inverse(A);
    float norm_A_inv = mat4_norm_frobenius(A_inv);
    return norm_A * norm_A_inv;
}

// --- LU Decomposition & Solving ---

static inline bool mat4_lu(Mat4 A, Mat4* L, Mat4* U, Mat4* P) {
    const float tolerance = 1e-6f;
    *U = A;
    *L = mat4_identity();
    *P = mat4_identity();

    for (int k = 0; k < 4; ++k) {
        int pivot_row = k;
        float max_val = fabsf(U->m[k][k]);
        for (int i = k + 1; i < 4; ++i) {
            float val = fabsf(U->m[k][i]);
            if (val > max_val) {
                max_val = val;
                pivot_row = i;
            }
        }

        if (max_val < tolerance) return false;

        if (pivot_row != k) {
            for (int j = 0; j < 4; ++j) {
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

        for (int i = k + 1; i < 4; ++i) {
            float factor = U->m[k][i] / U->m[k][k];
            L->m[k][i] = factor;
            for (int j = k; j < 4; ++j) {
                U->m[j][i] -= factor * U->m[j][k];
            }
        }
    }
    return true;
}

static inline Vec4 forward_substitution_mat4(Mat4 L, Vec4 b) {
    Vec4 x;
    float* x_arr = &x.x;
    x_arr[0] = b.x / L.m[0][0];
    x_arr[1] = (b.y - L.m[0][1] * x_arr[0]) / L.m[1][1];
    x_arr[2] = (b.z - (L.m[0][2] * x_arr[0] + L.m[1][2] * x_arr[1])) / L.m[2][2];
    x_arr[3] = (b.w - (L.m[0][3] * x_arr[0] + L.m[1][3] * x_arr[1] + L.m[2][3] * x_arr[2])) / L.m[3][3];
    return x;
}

static inline Vec4 backward_substitution_mat4(Mat4 U, Vec4 b) {
    Vec4 x;
    float* x_arr = &x.x;
    x_arr[3] = b.w / U.m[3][3];
    x_arr[2] = (b.z - U.m[3][2] * x_arr[3]) / U.m[2][2];
    x_arr[1] = (b.y - (U.m[2][1] * x_arr[2] + U.m[3][1] * x_arr[3])) / U.m[1][1];
    x_arr[0] = (b.x - (U.m[1][0] * x_arr[1] + U.m[2][0] * x_arr[2] + U.m[3][0] * x_arr[3])) / U.m[0][0];
    return x;
}

static inline Vec4 mat4_solve(Mat4 A, Vec4 b) {
    Mat4 L, U, P;
    if (!mat4_lu(A, &L, &U, &P)) {
        return (Vec4){0};
    }
    Vec4 Pb;
    Pb.x = P.m[0][0] * b.x + P.m[1][0] * b.y + P.m[2][0] * b.z + P.m[3][0] * b.w;
    Pb.y = P.m[0][1] * b.x + P.m[1][1] * b.y + P.m[2][1] * b.z + P.m[3][1] * b.w;
    Pb.z = P.m[0][2] * b.x + P.m[1][2] * b.y + P.m[2][2] * b.z + P.m[3][2] * b.w;
    Pb.w = P.m[0][3] * b.x + P.m[1][3] * b.y + P.m[2][3] * b.z + P.m[3][3] * b.w;

    Vec4 y = forward_substitution_mat4(L, Pb);
    return backward_substitution_mat4(U, y);
}

static inline Vec3 mat3_solve(Mat3 A, Vec3 b) {
    Mat3 L, U, P;
    if (!mat3_lu(A, &L, &U, &P)) return (Vec3){0};

    Vec3 Pb;
    Pb.x = P.m[0][0] * b.x + P.m[1][0] * b.y + P.m[2][0] * b.z;
    Pb.y = P.m[0][1] * b.x + P.m[1][1] * b.y + P.m[2][1] * b.z;
    Pb.z = P.m[0][2] * b.x + P.m[1][2] * b.y + P.m[2][2] * b.z;

    Vec3 y = forward_substitution_mat3(L, Pb);
    return backward_substitution_mat3(U, y);
}

/* ==================================================
   Graphics Extensions
   ================================================== */

/**
 * @brief Decomposes a TRS model matrix into scale, rotation, and translation.
 *
 * Inverse of mat4_compose(). The matrix is assumed to have the form T*R*S
 * (no skew/shear), which is what scene graphs produce.
 *
 * @param[in]  m           Model matrix to decompose.
 * @param[out] out_scale   Absolute scale per axis. Negative X indicates a
 *                         mirrored transform (negative determinant).
 * @param[out] out_rotation Unit rotation quaternion.
 * @param[out] out_translation World position.
 */
static inline void mat4_decompose(Mat4 m, Vec3* out_scale, Quat* out_rotation, Vec3* out_translation) {
    SimdVec3 c0 = {.v = m.cols[0]};
    SimdVec3 c1 = {.v = m.cols[1]};
    SimdVec3 c2 = {.v = m.cols[2]};
    SimdVec3 c3 = {.v = m.cols[3]};

    *out_translation = vec3_store(c3);

    // Scale is the length of each rotated basis column.
    float sx = vec3_length(c0);
    float sy = vec3_length(c1);
    float sz = vec3_length(c2);

    // Mirror detection via the sign of the upper-3x3 determinant.
    Mat3 rot_only;
    if (sx > 1e-12f && sy > 1e-12f && sz > 1e-12f) {
        rot_only = (Mat3){
            {{c0.x / sx, c0.y / sx, c0.z / sx}, {c1.x / sy, c1.y / sy, c1.z / sy}, {c2.x / sz, c2.y / sz, c2.z / sz}}};
        if (mat3_determinant(rot_only) < 0.0f) {
            sx = -sx;
            // Re-normalize column 0 with the corrected sign.
            rot_only.m[0][0] = -rot_only.m[0][0];
            rot_only.m[0][1] = -rot_only.m[0][1];
            rot_only.m[0][2] = -rot_only.m[0][2];
        }
    } else {
        rot_only = mat3_identity();
    }

    *out_scale = (Vec3){sx, sy, sz};

    Mat4 rot4 = mat4_identity();
    for (int c = 0; c < 3; c++) {
        for (int r = 0; r < 3; r++) {
            rot4.m[c][r] = rot_only.m[c][r];
        }
    }
    *out_rotation = quat_from_mat4(rot4);
}

/**
 * @brief Builds a tangent-space orthonormal basis around a surface normal.
 *
 * Returns two unit vectors perpendicular to @p normal (and to each other),
 * suitable for tangent/bitangent frames in normal mapping, TBN matrices,
 * and hemisphere sampling.
 *
 * @param normal Surface normal (normalized internally; zero-safe).
 * @return OrthonormalBasis with v0 = tangent, v1 = bitangent, v2 = normal.
 */
static inline OrthonormalBasis basis_from_normal(Vec3 normal) {
    SimdVec3 n = vec3_load(normal);
    float len_sq = vec3_length_sq(n);
    if (len_sq < 1e-12f) {
        return (OrthonormalBasis){(Vec3){1, 0, 0}, (Vec3){0, 1, 0}, (Vec3){0, 0, 1}};
    }
    n = vec3_mul(n, 1.0f / sqrtf(len_sq));

    // Pick the world axis the normal is LEAST parallel to so the cross
    // product is well-conditioned.
    SimdVec3 helper = (fabsf(n.x) < 0.9f) ? vec3_load((Vec3){1, 0, 0}) : vec3_load((Vec3){0, 1, 0});

    SimdVec3 tangent = vec3_normalize(vec3_cross(helper, n));
    SimdVec3 bitangent = vec3_cross(n, tangent);

    return (OrthonormalBasis){vec3_store(tangent), vec3_store(bitangent), vec3_store(n)};
}

/* ==================================================
   General Dense Matrix (row-major) & SVD
   ================================================== */

/**
 * @struct FMat
 * @brief Dynamically allocated dense float matrix in row-major order.
 *
 * Complements the fixed-size Mat3/Mat4 types when dimensions are only
 * known at runtime. Storage is a single malloc'd block; free it with
 * fmat_destroy(). All fmat_* functions are NOT thread-safe on the same
 * instance (like most container types here).
 */
typedef struct {
    size_t rows;
    size_t cols;
    float* data; /**< Row-major element block, rows * cols floats. */
} FMat;

/**
 * @brief Creates a zero-initialized rows x cols matrix.
 * @return The matrix; check .data == NULL to detect allocation failure.
 */
static inline FMat fmat_create(size_t rows, size_t cols) {
    FMat m = {rows, cols, NULL};
    if (rows > 0 && cols > 0) {
        m.data = (float*)calloc(rows * cols, sizeof(float));
    }
    return m;
}

/** @brief Frees the matrix's storage and resets it to an empty state. Safe on empty matrices. */
static inline void fmat_destroy(FMat* m) {
    if (m) {
        free(m->data);
        m->data = NULL;
        m->rows = 0;
        m->cols = 0;
    }
}

/** @brief True if the matrix holds allocated storage. */
static inline bool fmat_valid(const FMat* m) { return m && m->rows > 0 && m->cols > 0 && m->data != NULL; }

/**
 * @brief Element access (row, col), zero-indexed.
 * @warning No bounds checking — caller must ensure r < rows, c < cols.
 */
static inline float fmat_get(const FMat* m, size_t r, size_t c) { return m->data[r * m->cols + c]; }

/** @brief Element write (row, col), zero-indexed. */
static inline void fmat_set(FMat* m, size_t r, size_t c, float v) { m->data[r * m->cols + c] = v; }

/**
 * @brief Creates a new matrix initialized from a row-major value array.
 * @param values Must contain at least rows * cols floats.
 */
static inline FMat fmat_from_array(size_t rows, size_t cols, const float* values) {
    FMat m = fmat_create(rows, cols);
    if (m.data && values) {
        memcpy(m.data, values, rows * cols * sizeof(float));
    }
    return m;
}

/** @brief Deep copy of a matrix. Returns an invalid matrix if src is invalid or allocation fails. */
static inline FMat fmat_copy(const FMat* src) {
    if (!fmat_valid(src)) {
        FMat empty = {0, 0, NULL};
        return empty;
    }
    return fmat_from_array(src->rows, src->cols, src->data);
}

/** @brief n x n identity matrix. */
static inline FMat fmat_identity(size_t n) {
    FMat m = fmat_create(n, n);
    for (size_t i = 0; i < n; i++) {
        fmat_set(&m, i, i, 1.0f);
    }
    return m;
}

/** @brief Transpose of a matrix. Returns an invalid matrix if input is invalid. */
static inline FMat fmat_transpose(const FMat* m) {
    FMat t = {0, 0, NULL};
    if (!fmat_valid(m)) return t;
    t = fmat_create(m->cols, m->rows);
    if (!t.data) return t;
    for (size_t r = 0; r < m->rows; r++) {
        for (size_t c = 0; c < m->cols; c++) {
            fmat_set(&t, c, r, fmat_get(m, r, c));
        }
    }
    return t;
}

/**
 * @brief Matrix product a * b.
 * @return New matrix, or an invalid matrix ({NULL}) on dimension mismatch
 *         or allocation failure.
 */
static inline FMat fmat_mul(const FMat* a, const FMat* b) {
    FMat out = {0, 0, NULL};
    if (!fmat_valid(a) || !fmat_valid(b) || a->cols != b->rows) return out;
    out = fmat_create(a->rows, b->cols);
    if (!out.data) return out;
    for (size_t r = 0; r < a->rows; r++) {
        for (size_t k = 0; k < a->cols; k++) {
            const float aik = fmat_get(a, r, k);
            if (aik == 0.0f) continue;
            for (size_t c = 0; c < b->cols; c++) {
                fmat_set(&out, r, c, fmat_get(&out, r, c) + aik * fmat_get(b, k, c));
            }
        }
    }
    return out;
}

/**
 * @brief Copies a fixed-size Mat4 into a dynamically allocated FMat.
 * Useful for feeding Mat4 transforms into fmat_* batch operations.
 */
static inline FMat fmat_from_mat4(const Mat4* m) {
    FMat out = {0, 0, NULL};
    if (!m) return out;
    out = fmat_create(4, 4);
    if (!out.data) return out;
    // Mat4 stores column-major (m[col][row]); FMat is row-major, so the
    // copy transposes indices to keep both representing the same matrix.
    for (size_t c = 0; c < 4; c++) {
        for (size_t r = 0; r < 4; r++) {
            fmat_set(&out, r, c, m->m[c][r]);
        }
    }
    return out;
}

/**
 * @brief Transforms N homogeneous 4-component points by a 4x4 matrix.
 *
 * This is the batched vertex-transform workhorse of a software graphics
 * pipeline: instead of per-point function calls, the whole vertex buffer
 * goes through one GEMM. Points are rows [x y z w] of an N x 4 matrix.
 *
 * @param m     4 x 4 transform (e.g., model-view-projection).
 * @param points N x 4 row-major homogeneous points.
 * @return New N x 4 matrix of transformed points, or an invalid matrix
 *         ({NULL}) on bad input or allocation failure.
 */
static inline FMat fmat_batch_transform(const Mat4* m, const FMat* points) {
    if (!m || !fmat_valid(points) || points->cols != 4) {
        FMat empty = {0, 0, NULL};
        return empty;
    }
    // Row-vector times matrix: p' = p * M matches mat4_mul_vec4 semantics
    // (column-major M). Compute it as a single GEMM via transpose trick:
    // (P * M)^T = M^T * P^T, so transpose both and flip the product.
    FMat pt_t = fmat_transpose(points); /* 4 x N */
    if (!pt_t.data) {
        FMat empty = {0, 0, NULL};
        return empty;
    }

    FMat mt = fmat_create(4, 4);
    if (!mt.data) {
        fmat_destroy(&pt_t);
        FMat empty = {0, 0, NULL};
        return empty;
    }
    for (size_t c = 0; c < 4; c++) {
        for (size_t r = 0; r < 4; r++) {
            fmat_set(&mt, c, r, m->m[r][c]); /* mt = M^T */
        }
    }

    FMat out_t = fmat_mul(&mt, &pt_t); /* 4 x N */
    fmat_destroy(&mt);
    fmat_destroy(&pt_t);

    FMat out = fmat_transpose(&out_t); /* N x 4 */
    fmat_destroy(&out_t);
    return out;
}

/* --- One-sided Jacobi SVD internals ------------------------------------- */

#define FMAT_SVD_MAX_SWEEPS 60

/** Computes the dot product of columns i and j of a p x q row-major matrix. */
static inline float fmat_svd_col_dot(const float* data, size_t q, size_t p, size_t i, size_t j) {
    float sum = 0.0f;
    for (size_t r = 0; r < p; r++) {
        sum += data[r * q + i] * data[r * q + j];
    }
    return sum;
}

/** Rotates columns i and j of both matrices by the Givens rotation [c, s; -s, c]. */
static inline void fmat_svd_rotate_cols(float* restrict b, float* restrict v, size_t q, size_t p, size_t i, size_t j,
                                        float c, float s) {
    for (size_t r = 0; r < p; r++) {
        const float bi = b[r * q + i];
        const float bj = b[r * q + j];
        b[r * q + i] = c * bi - s * bj;
        b[r * q + j] = s * bi + c * bj;
    }
    for (size_t r = 0; r < q; r++) {
        // v is q x q: column rotations touch full columns.
        const float vi = v[r * q + i];
        const float vj = v[r * q + j];
        v[r * q + i] = c * vi - s * vj;
        v[r * q + j] = s * vi + c * vj;
    }
}

/**
 * @brief Singular Value Decomposition of an arbitrary M x N matrix.
 *
 * Computes the thin SVD A = U * diag(S) * V^T using one-sided Jacobi
 * orthogonalization, which is backward stable, accurate to ~machine
 * epsilon relative to the largest singular value, and handles rank
 * deficiency gracefully.
 *
 * Output shapes (thin SVD, k = min(m, n)):
 *   - U: m x k with orthonormal columns (left singular vectors)
 *   - S: k x 1 singular values in descending order
 *   - V: n x k with orthonormal columns (right singular vectors)
 *
 * For rank-deficient inputs, columns of U whose singular value is below
 * max_sigma * 1e-6 (or zero sigma entirely) are zeroed instead of being
 * arbitrary completions of the basis.
 *
 * @param[in]  A Input matrix (must be valid).
 * @param[out] U_out Receives the m x k left factor.
 * @param[out] S_out Receives the k x 1 singular-value vector.
 * @param[out] V_out Receives the n x n right factor.
 * @return true on success; false on invalid input, allocation failure,
 *         or failure to converge within FMAT_SVD_MAX_SWEEPS sweeps.
 *
 * @note Complexity is O(sweeps * m * n * min(m,n)); fine for moderate
 *       sizes but not a substitute for LAPACK on very large matrices.
 *
 * @example
 *   FMat a = fmat_from_array(2, 2, (float[]){4, 0, 3, -5});
 *   FMat u, s, v;
 *   fmat_svd(&a, &u, &s, &v);      // a = u diag(s) v^T
 *   ...
 *   fmat_destroy(&a); fmat_destroy(&u); fmat_destroy(&s); fmat_destroy(&v);
 */
static inline bool fmat_svd(const FMat* A, FMat* U_out, FMat* S_out, FMat* V_out) {
    if (U_out) *U_out = (FMat){0, 0, NULL};
    if (S_out) *S_out = (FMat){0, 0, NULL};
    if (V_out) *V_out = (FMat){0, 0, NULL};
    if (!fmat_valid(A) || !U_out || !S_out || !V_out) return false;

    const size_t m = A->rows;
    const size_t n = A->cols;
    const size_t k = (m < n) ? m : n;

    /*
     * One-sided Jacobi needs tall-or-square input. For wide matrices,
     * decompose A^T instead: A^T = Ub S Vb^T  =>  A = Vb S Ub^T.
     */
    const bool transposed = (m < n);
    const size_t p = transposed ? n : m;  // working row count (>= q)
    const size_t q = k;                   // working column count

    FMat B = {0, 0, NULL};     // working copy of A (or A^T), p x q
    FMat Vacc = {0, 0, NULL};  // accumulated right rotations, q x q
    FMat work_U = {0, 0, NULL}, work_S = {0, 0, NULL}, work_V = {0, 0, NULL};
    FMat Uf = {0, 0, NULL}, Sf = {0, 0, NULL}, Vf = {0, 0, NULL};  // sorted factors
    size_t* order = (size_t*)malloc(q * sizeof(size_t));

    bool ok = false;
    do {
        if (!order) break;
        if (transposed) {
            FMat At = fmat_transpose(A);
            if (!fmat_valid(&At)) break;
            B = At;  // ownership moves to B
        } else {
            B = fmat_copy(A);
            if (!fmat_valid(&B)) break;
        }

        Vacc = fmat_identity(q);
        if (!fmat_valid(&Vacc)) break;

        /* Jacobi sweeps: rotate column pairs until all are mutually
         * orthogonal (off-diagonal entries of B^T B vanish). */
        const float ortho_tol = 1e-7f;
        bool converged = false;
        for (unsigned sweep = 0; sweep < FMAT_SVD_MAX_SWEEPS && !converged; sweep++) {
            converged = true;
            for (size_t i = 0; i + 1 < q; i++) {
                for (size_t j = i + 1; j < q; j++) {
                    const float alpha = fmat_svd_col_dot(B.data, q, p, i, i);
                    const float beta = fmat_svd_col_dot(B.data, q, p, j, j);
                    const float gamma = fmat_svd_col_dot(B.data, q, p, i, j);

                    // Zero (or denormal-tiny) columns are already orthogonal
                    // to everything; rotating them would stall convergence.
                    if (alpha < 1e-20f || beta < 1e-20f) continue;
                    if (fabsf(gamma) <= ortho_tol * sqrtf(alpha * beta)) continue;

                    converged = false;
                    // Rotation angle that zeroes gamma (Rutishauser).
                    const float zeta = (beta - alpha) / (2.0f * gamma);
                    const float t = ((zeta >= 0.0f) ? 1.0f : -1.0f) / (fabsf(zeta) + sqrtf(1.0f + zeta * zeta));
                    const float c = 1.0f / sqrtf(1.0f + t * t);
                    const float s = c * t;
                    fmat_svd_rotate_cols(B.data, Vacc.data, q, p, i, j, c, s);
                }
            }
        }
        if (!converged) break;

        /* Extract singular values and normalize the working columns into U. */
        work_U = fmat_create(p, q);
        work_S = fmat_create(q, 1);
        work_V = fmat_copy(&Vacc);
        if (!fmat_valid(&work_U) || !fmat_valid(&work_S) || !fmat_valid(&work_V)) break;

        float sigma_max = 0.0f;
        for (size_t j = 0; j < q; j++) {
            float sum = 0.0f;
            for (size_t r = 0; r < p; r++) {
                const float val = B.data[r * q + j];
                sum += val * val;
                work_U.data[r * q + j] = val;
            }
            const float sigma = sqrtf(sum);
            work_S.data[j] = sigma;
            if (sigma > sigma_max) sigma_max = sigma;
        }

        // Normalize; near-zero directions get zeroed rather than arbitrary fill.
        const float rank_eps = sigma_max * 1e-6f;
        for (size_t j = 0; j < q; j++) {
            const float sigma = work_S.data[j];
            if (sigma <= rank_eps) {
                // Row-major storage: a column is strided, so zero element-wise.
                for (size_t r = 0; r < p; r++) {
                    work_U.data[r * q + j] = 0.0f;
                }
                continue;
            }
            const float inv = 1.0f / sigma;
            for (size_t r = 0; r < p; r++) {
                work_U.data[r * q + j] *= inv;
            }
        }

        /* Sort singular values (and matching vectors) in descending order. */
        for (size_t j = 0; j < q; j++) order[j] = j;
        for (size_t i = 0; i + 1 < q; i++) {
            size_t best = i;
            for (size_t j = i + 1; j < q; j++) {
                if (work_S.data[order[j]] > work_S.data[order[best]]) best = j;
            }
            if (best != i) {
                const size_t tswap = order[i];
                order[i] = order[best];
                order[best] = tswap;
            }
        }

        // Permute into final thin factors.
        Uf = fmat_create(p, q);
        Sf = fmat_create(q, 1);
        Vf = fmat_create(q, q);
        if (!fmat_valid(&Uf) || !fmat_valid(&Sf) || !fmat_valid(&Vf)) {
            break;
        }
        for (size_t jc = 0; jc < q; jc++) {
            const size_t src = order[jc];
            Sf.data[jc] = work_S.data[src];
            for (size_t r = 0; r < p; r++) {
                Uf.data[r * q + jc] = work_U.data[r * q + src];
            }
            for (size_t r = 0; r < q; r++) {
                Vf.data[r * q + jc] = work_V.data[r * q + src];
            }
        }

        if (transposed) {
            // A^T = Ub S Vb^T  =>  A = Vb S Ub^T.
            // Matching against A = U S V^T: U = Vb, V^T = Ub^T => V = Ub.
            *U_out = Vf;
            Vf = (FMat){0, 0, NULL};  // moved
            *S_out = Sf;
            Sf = (FMat){0, 0, NULL};  // moved
            *V_out = Uf;
            Uf = (FMat){0, 0, NULL};  // moved
        } else {
            *U_out = Uf;
            Uf = (FMat){0, 0, NULL};  // moved
            *S_out = Sf;
            Sf = (FMat){0, 0, NULL};  // moved
            *V_out = Vf;
            Vf = (FMat){0, 0, NULL};  // moved
        }
        ok = true;
    } while (0);

    /* Single unconditional cleanup. Every successful transfer zeroed its
     * source struct, so destroying the locals here can never double-free. */
    free(order);
    fmat_destroy(&B);
    fmat_destroy(&Vacc);
    fmat_destroy(&work_U);
    fmat_destroy(&work_S);
    fmat_destroy(&work_V);
    fmat_destroy(&Uf);
    fmat_destroy(&Sf);
    fmat_destroy(&Vf);
    return ok;
}

/* ==================================================
   ML Primitives: RNG, init, elementwise ops, activations,
   losses, backprop products, pseudo-inverse, PCA
   ================================================== */

/**
 * @struct FMatRng
 * @brief Tiny seeded PRNG state for reproducible weight initialization.
 *
 * Uses xoshiro-style bit mixing; statistically adequate for weight init
 * and synthetic datasets, not for cryptography or serious simulation.
 */
typedef struct {
    uint64_t state;
} FMatRng;

/** @brief Seeds the generator. Same seed => same sequence on every platform. */
static inline void fmat_rng_seed(FMatRng* rng, uint64_t seed) { rng->state = seed ? seed : 0x9E3779B97F4A7C15ull; }

/** @brief Uniform float in [0, 1). */
static inline float fmat_rng_uniform(FMatRng* rng) {
    uint64_t z = (rng->state += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    return (float)(z >> 40) / (float)(1u << 24);
}

/**
 * @brief Standard normal sample via Box-Muller transform.
 * @note Consumes two uniforms per call.
 */
static inline float fmat_rng_normal(FMatRng* rng) {
    float u1 = fmat_rng_uniform(rng);
    if (u1 < 1e-12f) u1 = 1e-12f;  // log(0) guard
    const float u2 = fmat_rng_uniform(rng);
    return sqrtf(-2.0f * logf(u1)) * cosf(6.28318530717958647692f * u2);
}

/** @brief Fills every element with @p value. */
static inline bool fmat_fill(FMat* m, float value) {
    if (!fmat_valid(m)) return false;
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] = value;
    return true;
}

/** @brief Multiplies every element by @p s (in place). */
static inline bool fmat_scale_ip(FMat* m, float s) {
    if (!fmat_valid(m)) return false;
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] *= s;
    return true;
}

/** @brief Out-of-place scalar multiply. */
static inline FMat fmat_scale(const FMat* m, float s) {
    FMat r = fmat_copy(m);
    fmat_scale_ip(&r, s);
    return r;
}

/** @brief Element-wise sum a + b (in place into a). Shapes must match. */
static inline bool fmat_add_ip(FMat* a, const FMat* b) {
    if (!fmat_valid(a) || !fmat_valid(b) || a->rows != b->rows || a->cols != b->cols) return false;
    for (size_t i = 0; i < a->rows * a->cols; i++) a->data[i] += b->data[i];
    return true;
}

/** @brief Element-wise difference a - b (in place into a). Shapes must match. */
static inline bool fmat_sub_ip(FMat* a, const FMat* b) {
    if (!fmat_valid(a) || !fmat_valid(b) || a->rows != b->rows || a->cols != b->cols) return false;
    for (size_t i = 0; i < a->rows * a->cols; i++) a->data[i] -= b->data[i];
    return true;
}

/** @brief Out-of-place element-wise sum. */
static inline FMat fmat_add(const FMat* a, const FMat* b) {
    FMat r = fmat_copy(a);
    fmat_add_ip(&r, b);
    return r;
}

/** @brief Out-of-place element-wise difference. */
static inline FMat fmat_sub(const FMat* a, const FMat* b) {
    FMat r = fmat_copy(a);
    fmat_sub_ip(&r, b);
    return r;
}

/** @brief Out-of-place Hadamard (element-wise) product. Shapes must match. */
static inline FMat fmat_hadamard(const FMat* a, const FMat* b) {
    if (!fmat_valid(a) || !fmat_valid(b) || a->rows != b->rows || a->cols != b->cols) {
        FMat empty = {0, 0, NULL};
        return empty;
    }
    FMat r = fmat_create(a->rows, a->cols);
    for (size_t i = 0; i < a->rows * a->cols; i++) r.data[i] = a->data[i] * b->data[i];
    return r;
}

/**
 * @brief Broadcasts a 1 x cols row vector across every matrix row (in place).
 *
 * The canonical "add the bias" operation: Z += b where b is a layer's
 * bias vector replicated over the batch dimension.
 */
static inline bool fmat_add_row_vector(FMat* m, const FMat* row) {
    if (!fmat_valid(m) || !fmat_valid(row) || row->rows != 1 || row->cols != m->cols) return false;
    for (size_t r = 0; r < m->rows; r++) {
        for (size_t c = 0; c < m->cols; c++) {
            m->data[r * m->cols + c] += row->data[c];
        }
    }
    return true;
}

/** @brief Applies fn to every element, returning a new matrix. */
static inline FMat fmat_apply(const FMat* m, float (*fn)(float)) {
    FMat r = {0, 0, NULL};
    if (!fmat_valid(m) || !fn) return r;
    r = fmat_create(m->rows, m->cols);
    for (size_t i = 0; i < m->rows * m->cols; i++) r.data[i] = fn(m->data[i]);
    return r;
}

/**
 * @brief He (Kaiming) initialization: N(0, 2 / fan_in).
 * The standard init for ReLU-family networks.
 */
static inline bool fmat_he_init(FMat* m, size_t fan_in, FMatRng* rng) {
    if (!fmat_valid(m) || fan_in == 0 || !rng) return false;
    const float stddev = sqrtf(2.0f / (float)fan_in);
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] = fmat_rng_normal(rng) * stddev;
    return true;
}

/**
 * @brief Xavier/Glorot initialization: N(0, 2 / (fan_in + fan_out)).
 * The standard init for tanh/sigmoid-family networks.
 */
static inline bool fmat_xavier_init(FMat* m, size_t fan_in, size_t fan_out, FMatRng* rng) {
    if (!fmat_valid(m) || fan_in == 0 || fan_out == 0 || !rng) return false;
    const float stddev = sqrtf(2.0f / (float)(fan_in + fan_out));
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] = fmat_rng_normal(rng) * stddev;
    return true;
}

/* --- Reductions ---------------------------------------------------------- */

/** @brief Column sums as a fresh 1 x cols matrix. */
static inline FMat fmat_sum_cols(const FMat* m) {
    FMat r = {0, 0, NULL};
    if (!fmat_valid(m)) return r;
    r = fmat_create(1, m->cols);
    for (size_t row = 0; row < m->rows; row++) {
        for (size_t c = 0; c < m->cols; c++) {
            r.data[c] += m->data[row * m->cols + c];
        }
    }
    return r;
}

/** @brief Row sums as a fresh rows x 1 matrix. */
static inline FMat fmat_sum_rows(const FMat* m) {
    FMat r = {0, 0, NULL};
    if (!fmat_valid(m)) return r;
    r = fmat_create(m->rows, 1);
    for (size_t row = 0; row < m->rows; row++) {
        float sum = 0.0f;
        for (size_t c = 0; c < m->cols; c++) sum += m->data[row * m->cols + c];
        r.data[row] = sum;
    }
    return r;
}

/** @brief Column means as a fresh 1 x cols matrix. */
static inline FMat fmat_mean_cols(const FMat* m) {
    FMat r = fmat_sum_cols(m);
    if (r.data && m->rows > 0) {
        const float inv = 1.0f / (float)m->rows;
        for (size_t c = 0; c < r.cols; c++) r.data[c] *= inv;
    }
    return r;
}

/**
 * @brief Index of the maximum element of each row, returned as rows x 1 floats.
 * Typical use: converting softmax probabilities to predicted class ids.
 */
static inline FMat fmat_argmax_rows(const FMat* m) {
    FMat r = {0, 0, NULL};
    if (!fmat_valid(m)) return r;
    r = fmat_create(m->rows, 1);
    for (size_t row = 0; row < m->rows; row++) {
        size_t best = 0;
        float best_val = m->data[row * m->cols];
        for (size_t c = 1; c < m->cols; c++) {
            if (m->data[row * m->cols + c] > best_val) {
                best_val = m->data[row * m->cols + c];
                best = c;
            }
        }
        r.data[row] = (float)best;
    }
    return r;
}

/* --- Activations --------------------------------------------------------- */

static inline float fml_relu_f(float x) { return x > 0.0f ? x : 0.0f; }
static inline float fml_sigmoid_f(float x) { return 1.0f / (1.0f + expf(-x)); }
static inline float fml_tanh_f(float x) { return tanhf(x); }

/** @brief ReLU applied element-wise (out-of-place). */
static inline FMat fmat_relu(const FMat* m) { return fmat_apply(m, fml_relu_f); }

/** @brief ReLU applied in place. */
static inline bool fmat_relu_ip(FMat* m) {
    if (!fmat_valid(m)) return false;
    for (size_t i = 0; i < m->rows * m->cols; i++)
        if (m->data[i] < 0.0f) m->data[i] = 0.0f;
    return true;
}

/** @brief Logistic sigmoid applied element-wise (out-of-place). */
static inline FMat fmat_sigmoid(const FMat* m) { return fmat_apply(m, fml_sigmoid_f); }

/** @brief Logistic sigmoid applied in place. */
static inline bool fmat_sigmoid_ip(FMat* m) {
    if (!fmat_valid(m)) return false;
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] = fml_sigmoid_f(m->data[i]);
    return true;
}

/** @brief Hyperbolic tangent applied element-wise (out-of-place). */
static inline FMat fmat_tanh(const FMat* m) { return fmat_apply(m, fml_tanh_f); }

/** @brief Hyperbolic tangent applied in place. */
static inline bool fmat_tanh_ip(FMat* m) {
    if (!fmat_valid(m)) return false;
    for (size_t i = 0; i < m->rows * m->cols; i++) m->data[i] = tanhf(m->data[i]);
    return true;
}

/**
 * @brief Numerically stable row-wise softmax.
 *
 * Each row becomes a probability distribution (entries >= 0, row sum 1).
 * Subtracts the row max before exponentiating so large inputs cannot
 * overflow; this makes the result invariant to constant row shifts.
 */
static inline FMat fmat_softmax_rows(const FMat* m) {
    FMat r = {0, 0, NULL};
    if (!fmat_valid(m)) return r;
    r = fmat_create(m->rows, m->cols);
    if (!r.data) return r;
    for (size_t row = 0; row < m->rows; row++) {
        const float* src = &m->data[row * m->cols];
        float* dst = &r.data[row * m->cols];
        float max_val = src[0];
        for (size_t c = 1; c < m->cols; c++) {
            if (src[c] > max_val) max_val = src[c];
        }
        float sum = 0.0f;
        for (size_t c = 0; c < m->cols; c++) {
            dst[c] = expf(src[c] - max_val);
            sum += dst[c];
        }
        const float inv = (sum > 0.0f) ? 1.0f / sum : 0.0f;
        for (size_t c = 0; c < m->cols; c++) dst[c] *= inv;
    }
    return r;
}

/* --- Losses ---------------------------------------------------------------- */

/**
 * @brief Mean squared error over all elements: sum((a-b)^2) / count.
 * Returns -1.0f on shape mismatch or invalid input.
 */
static inline float fmat_mse(const FMat* a, const FMat* b) {
    if (!fmat_valid(a) || !fmat_valid(b) || a->rows != b->rows || a->cols != b->cols) return -1.0f;
    float sum = 0.0f;
    for (size_t i = 0; i < a->rows * a->cols; i++) {
        const float d = a->data[i] - b->data[i];
        sum += d * d;
    }
    return sum / (float)(a->rows * a->cols);
}

/**
 * @brief Mean categorical cross-entropy between softmax outputs and one-hot labels.
 *
 * Both matrices are samples x classes. Probabilities are clamped away
 * from zero to keep the log finite. Returns -1.0f on invalid input.
 */
static inline float fmat_cross_entropy(const FMat* probs, const FMat* onehot) {
    if (!fmat_valid(probs) || !fmat_valid(onehot) || probs->rows != onehot->rows || probs->cols != onehot->cols)
        return -1.0f;
    const float eps = 1e-12f;
    float sum = 0.0f;
    for (size_t i = 0; i < probs->rows * probs->cols; i++) {
        float p = probs->data[i];
        if (p < eps) p = eps;
        sum -= onehot->data[i] * logf(p);
    }
    return sum / (float)probs->rows;
}

/* --- Backprop-friendly products -------------------------------------------- */

/**
 * @brief Computes A^T * B without materializing the transpose.
 * A is m x n, B is m x p => result n x p. The gradient workhorse:
 * dW = X^T dZ falls exactly into this pattern.
 */
static inline FMat fmat_mul_ta(const FMat* a, const FMat* b) {
    FMat out = {0, 0, NULL};
    if (!fmat_valid(a) || !fmat_valid(b) || a->rows != b->rows) return out;
    out = fmat_create(a->cols, b->cols);
    if (!out.data) return out;
    for (size_t k = 0; k < a->rows; k++) {
        for (size_t i = 0; i < a->cols; i++) {
            const float aik = a->data[k * a->cols + i];
            if (aik == 0.0f) continue;
            for (size_t j = 0; j < b->cols; j++) {
                out.data[i * b->cols + j] += aik * b->data[k * b->cols + j];
            }
        }
    }
    return out;
}

/**
 * @brief Computes A * B^T without materializing the transpose.
 * A is m x n, B is p x n => result m x p. Used for propagating deltas:
 * dH = dZ * W^T.
 */
static inline FMat fmat_mul_tb(const FMat* a, const FMat* b) {
    FMat out = {0, 0, NULL};
    if (!fmat_valid(a) || !fmat_valid(b) || a->cols != b->cols) return out;
    out = fmat_create(a->rows, b->rows);
    if (!out.data) return out;
    for (size_t i = 0; i < a->rows; i++) {
        for (size_t j = 0; j < b->rows; j++) {
            float sum = 0.0f;
            for (size_t k = 0; k < a->cols; k++) {
                sum += a->data[i * a->cols + k] * b->data[j * b->cols + k];
            }
            out.data[i * b->rows + j] = sum;
        }
    }
    return out;
}

/* --- Pseudo-inverse & least squares ----------------------------------------- */

/**
 * @brief Moore-Penrose pseudo-inverse via SVD: A^+ = V diag(s^-1) U^T.
 *
 * Singular values below max_sigma * tol (default 1e-6) are treated as
 * zero, which regularizes ill-conditioned/rank-deficient systems.
 *
 * @param[in] A m x n matrix.
 * @param[out] out Receives the n x m pseudo-inverse.
 * @return true on success.
 */
static inline bool fmat_pinv(const FMat* A, FMat* out) {
    if (out) *out = (FMat){0, 0, NULL};
    if (!fmat_valid(A) || !out) return false;

    FMat u = {0, 0, NULL}, s = {0, 0, NULL}, v = {0, 0, NULL};
    if (!fmat_svd(A, &u, &s, &v)) return false;

    const size_t kk = s.rows;
    const float sigma_max = fmat_get(&s, 0, 0);
    const float cutoff = sigma_max * 1e-6f;

    // W = V * diag(1/sigma): scale each column of V by the inverted sigma.
    FMat w = fmat_copy(&v);
    bool ok = false;
    do {
        if (!w.data) break;
        for (size_t j = 0; j < kk; j++) {
            const float sigma = fmat_get(&s, j, 0);
            if (sigma <= cutoff) continue;
            const float inv = 1.0f / sigma;
            for (size_t r = 0; r < w.rows; r++) {
                fmat_set(&w, r, j, fmat_get(&w, r, j) * inv);
            }
        }
        // A^+ = W * U^T (n x k times k-scaled -> n x m).
        *out = fmat_mul_tb(&w, &u);
        ok = (out->data != NULL);
    } while (0);

    fmat_destroy(&u);
    fmat_destroy(&s);
    fmat_destroy(&v);
    fmat_destroy(&w);
    return ok;
}

/**
 * @brief Solves min_x ||A x - b||_2 via the pseudo-inverse.
 * Works for square, overdetermined, and rank-deficient systems.
 *
 * @param[in] A m x n design matrix.
 * @param[in] b m x 1 targets.
 * @param[out] out Receives the n x 1 solution.
 */
static inline bool fmat_lstsq(const FMat* A, const FMat* b, FMat* out) {
    if (out) *out = (FMat){0, 0, NULL};
    if (!fmat_valid(A) || !fmat_valid(b) || b->cols != 1 || A->rows != b->rows) return false;

    FMat apinv = {0, 0, NULL};
    if (!fmat_pinv(A, &apinv)) return false;
    *out = fmat_mul(&apinv, b);
    fmat_destroy(&apinv);
    return (out->data != NULL);
}

/* --- Principal Component Analysis -------------------------------------------- */

/**
 * @struct PCAResult
 * @brief Fitted PCA model: principal axes plus dataset statistics.
 */
typedef struct {
    FMat components;      /**< n_components x n_features, orthonormal rows. */
    FMat mean;            /**< 1 x n_features column means of the training data. */
    FMat explained_ratio; /**< n_components x 1 fraction of variance captured. */
} PCAResult;

/** @brief Releases all storage owned by a PCA model. Safe to call twice. */
static inline void pca_result_destroy(PCAResult* pca) {
    if (!pca) return;
    fmat_destroy(&pca->components);
    fmat_destroy(&pca->mean);
    fmat_destroy(&pca->explained_ratio);
}

/**
 * @brief Fits PCA on a samples x features matrix using the library's SVD.
 *
 * Data is centered internally; the top @p n_components principal axes are
 * the leading right-singular vectors of the centered data. Requires
 * n_components <= min(samples, features).
 *
 * @param[in] X Samples stored as rows.
 * @param[in] n_components Number of axes to keep.
 * @param[out] out Receives the fitted model.
 * @return true on success.
 */
static inline bool fmat_pca(const FMat* X, size_t n_components, PCAResult* out) {
    if (out) {
        out->components = (FMat){0, 0, NULL};
        out->mean = (FMat){0, 0, NULL};
        out->explained_ratio = (FMat){0, 0, NULL};
    }
    if (!fmat_valid(X) || !out || n_components == 0) return false;

    const size_t m = X->rows;
    const size_t n = X->cols;
    const size_t kmax = (m < n) ? m : n;
    if (n_components > kmax) return false;

    bool ok = false;
    FMat xc = fmat_copy(X);
    FMat u = {0, 0, NULL}, s = {0, 0, NULL}, v = {0, 0, NULL};
    FMat means = {0, 0, NULL};
    do {
        // Center the data.
        means = fmat_mean_cols(X);
        if (!means.data) break;
        for (size_t r = 0; r < m; r++) {
            for (size_t c = 0; c < n; c++) {
                xc.data[r * n + c] -= means.data[c];
            }
        }

        if (!fmat_svd(&xc, &u, &s, &v)) break;

        out->components = fmat_create(n_components, n);
        out->mean = means;
        means = (FMat){0, 0, NULL};  // moved
        out->explained_ratio = fmat_create(n_components, 1);
        if (!out->components.data || !out->explained_ratio.data) break;

        // Total captured variance across all available directions.
        float total_var = 0.0f;
        for (size_t j = 0; j < s.rows; j++) {
            const float var = fmat_get(&s, j, 0) * fmat_get(&s, j, 0) / (float)(m > 1 ? m - 1 : 1);
            total_var += var;
        }
        for (size_t j = 0; j < n_components; j++) {
            // Row j of components = column j of V.
            for (size_t c = 0; c < n; c++) {
                fmat_set(&out->components, j, c, fmat_get(&v, c, j));
            }
            const float var = fmat_get(&s, j, 0) * fmat_get(&s, j, 0) / (float)(m > 1 ? m - 1 : 1);
            fmat_set(&out->explained_ratio, j, 0, total_var > 0.0f ? var / total_var : 0.0f);
        }
        ok = true;
    } while (0);

    fmat_destroy(&xc);
    fmat_destroy(&u);
    fmat_destroy(&s);
    fmat_destroy(&v);
    fmat_destroy(&means);
    if (!ok) pca_result_destroy(out);
    return ok;
}

/**
 * @brief Projects samples onto the retained principal axes.
 *
 * Equivalent to (X - mean) * components^T, producing samples x n_components
 * coordinates suitable for visualization or downstream models.
 */
static inline FMat fmat_pca_transform(const PCAResult* pca, const FMat* X) {
    FMat r = {0, 0, NULL};
    if (!pca || !pca->components.data || !pca->mean.data || !fmat_valid(X)) return r;
    if (X->cols != pca->mean.cols) return r;

    FMat xc = fmat_copy(X);
    if (!xc.data) return r;
    for (size_t row = 0; row < xc.rows; row++) {
        for (size_t c = 0; c < xc.cols; c++) {
            xc.data[row * xc.cols + c] -= pca->mean.data[c];
        }
    }
    FMat ct = fmat_transpose(&pca->components);
    r = fmat_mul(&xc, &ct);
    fmat_destroy(&xc);
    fmat_destroy(&ct);
    return r;
}

#ifdef __cplusplus
}
#endif

#endif  // LINEAR_ALG_H
