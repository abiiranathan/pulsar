/**
 * @file sort.h
 * @brief Faster alternatives to qsort(): a generic introsort drop-in and
 *        branchless type-specialized sorts with zero callback overhead.
 *
 * Why faster than glibc qsort():
 *  - sol_qsort(): same signature, but median-of-three/ninther pivots,
 *    insertion sort on short ranges, heapsort depth-bounding (guaranteed
 *    O(n log n) worst case), and swap kernels tuned for small element
 *    sizes.  Gains are workload-dependent (~1.1-1.6x on trivial
 *    comparators).
 *  - sol_sort_i32/i64/f64(): no comparator AT ALL -- direct relational
 *    compares let the compiler emit branchless partitions (conditional
 *    moves).  Typically 3-8x faster than qsort on numeric data.
 *
 * None of these sorts are stable.  f64 sorts NaNs to the END of the
 * array (order among NaNs unspecified).
 */

#ifndef SOLIDC_SORT_H
#define SOLIDC_SORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Drop-in qsort replacement. NULL-safe: NULL base, zero/one elements,
 *  zero size, or NULL compar are accepted as no-ops. */
void sol_qsort(void* base, size_t n, size_t size, int (*compar)(const void*, const void*));

/** Branchless sorts without callbacks. NaNs sort to the end for f64. */
void sol_sort_i32(int32_t* a, size_t n);
void sol_sort_i64(int64_t* a, size_t n);
void sol_sort_f64(double* a, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_SORT_H */
