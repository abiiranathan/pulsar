/**
 * @file defer.h
 * References:
 * - https://gustedt.wordpress.com/2025/01/06/simple-defer-ready-to-use/
 * - https://thephd.dev/c2y-the-defer-technical-specification-its-time-go-go-go
 * - https://gcc.gnu.org/onlinedocs/gccint/Trampolines.html
 * - https://github.com/moon-chilled/Defer/blob/master/defer.h
 *
 * @brief Cross-platform defer statement for automatic resource cleanup.
 *
 * Provides a 'defer' statement that executes a code block when the current
 * scope exits, similar to Go's defer or C++ RAII scope guards. Multiple
 * deferred blocks in the same scope execute in reverse declaration order.
 *
 *
 * @section compilation Compilation Instructions
 *
 * C++ (any compiler):
 *   g++ main.cpp / clang++ main.cpp / cl main.cpp
 *   No special flags required — uses RAII with lambdas.
 *
 * C with GCC 4.9+:
 *   gcc main.c
 *   Uses nested functions with 'auto' storage class (no trampolines,
 *   no executable stack required).
 *
 * C with Clang:
 *   clang -fblocks -lBlocksRuntime main.c
 *   Requires the blocks runtime library.
 *   Install: Ubuntu/Debian — sudo apt-get install libblocksruntime-dev
 *            Arch Linux    — sudo pacman -S libdispatch
 *
 * C with MSVC:
 *   cl main.c
 *   Uses __try/__finally (no special flags required).
 *
 * @section syntax Usage
 *
 * GCC / Clang (C):
 * @code
 *   defer { fclose(f); }         // block, no trailing semicolon needed
 *   defer { free(ptr); }
 * @endcode
 *
 * C++ and MSVC:
 * @code
 *   defer { fclose(f); };        // trailing semicolon required
 *   defer { free(ptr); };
 * @endcode
 *
 * @warning Do NOT use 'return', 'break', 'goto', or 'continue' inside a
 *          deferred block. The behaviour is undefined in all backends.
 *
 * @warning Variables captured by a deferred block must remain in scope and
 *          not be modified between the defer declaration and scope exit in
 *          ways that would invalidate the cleanup (e.g. do not reassign a
 *          pointer after defer_free-ing it without zeroing first).
 *=================================================================================*/
#ifndef DEFER_H
#define DEFER_H

#if defined(__clang__) && !defined(__cplusplus)
    #define DEFER_VAR __block
#else
    #define DEFER_VAR
#endif

/* token-paste used by all backends. */
#define _DEFER_CONCAT_IMPL(a, b) a##b
#define _DEFER_CONCAT(a, b)      _DEFER_CONCAT_IMPL(a, b)

/*
 * ATTR_UNUSED suppresses unused-variable warnings for the internal cleanup
 * trigger variables emitted by the GCC and Clang backends.
 */
#ifdef _WIN32
    #define ATTR_UNUSED
#else
    #define ATTR_UNUSED __attribute__((__unused__))
#endif

/* ============================================================
 * C++ — RAII via lambda + destructor
 * ============================================================ */
#ifdef __cplusplus

    #include <utility> /* std::forward */

/**
 * @brief RAII holder that invokes a callable on destruction.
 * @tparam F Callable type (lambda, function object).
 */
template <typename F>
struct _DeferHolder {
    F f;
    explicit _DeferHolder(F&& func) : f(std::forward<F>(func)) {}
    ~_DeferHolder() { f(); }
    _DeferHolder(const _DeferHolder&) = delete;
    _DeferHolder& operator=(const _DeferHolder&) = delete;
};

/** @brief Tag type used to trigger operator+ overload syntax. */
struct _DeferHelper {};

/**
 * @brief Captures a lambda into a _DeferHolder via operator+ syntax.
 * @tparam F Callable type.
 */
template <typename F>
_DeferHolder<F> operator+(_DeferHelper, F&& f) {
    return _DeferHolder<F>(std::forward<F>(f));
}

    /*
     * Expands to:
     *   auto _defer_var_N = _DeferHelper() + [&]() { <user block> };
     *
     * The trailing semicolon must be supplied by the caller:
     *   defer { cleanup(); };
     */
    #define defer auto _DEFER_CONCAT(_defer_var_, __COUNTER__) = _DeferHelper() + [&]()

/* ============================================================
 * C / GCC — nested functions with 'auto' storage class
 * ============================================================
 *
 * Requires GCC 4.9+. The 'auto' keyword applied to a nested function
 * restricts it to automatic storage duration, allowing the compiler to
 * implement it without a trampoline (no executable stack pages needed).
 *
 * __attribute__((cleanup(F))) causes F to be called with a pointer to V
 * when V goes out of scope. V itself is unused; it is only the trigger.
 */
#elif defined(__GNUC__) && !defined(__clang__)

    #if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 9)
        #error "defer.h: GCC 4.9 or later is required for nested-function auto storage class."
    #endif

    #define _DEFER_MAKE(F, V)                  \
        auto void F(int*);                     \
        [[gnu::cleanup(F)]] ATTR_UNUSED int V; \
        auto void F(int* _unused ATTR_UNUSED)

    #define _DEFER_N(N) _DEFER_MAKE(_DEFER_CONCAT(_defer_fn_, N), _DEFER_CONCAT(_defer_var_, N))

    /*
     * Expands to an inline nested-function definition whose body is the
     * user's block:
     *   defer { cleanup(); }   ← no trailing semicolon required
     */
    #define defer       _DEFER_N(__COUNTER__)

/* ============================================================
 * C / Clang — Blocks extension
 * ============================================================
 *
 * Requires -fblocks and -lBlocksRuntime.
 * Blocks capture variables from the enclosing scope by reference
 * (via ^{ }) and are stack-allocated by default.
 */
#elif defined(__clang__)

    #include <Block.h> /* Block.h from BlocksRuntime */

/** @brief Block type used as the deferred cleanup handler. */
typedef void (^_defer_block_t)(void);

/**
 * @brief __attribute__((cleanup)) handler for deferred blocks.
 * @param blk Pointer to the block variable going out of scope.
 */
static inline void _defer_cleanup_block(_defer_block_t* blk) {
    if (blk && *blk) {
        (*blk)();
    }
}

    /*
     * Expands to:
     *   __attribute__((cleanup(...))) _defer_block_t _defer_var_N = ^{ <user block> }
     *
     * The block literal (^{ }) captures surrounding locals by value automatically (unless __block type is specified)
     *   defer { cleanup(); };   ← trailing semicolon required
     */
    #define defer                                                                                            \
        __attribute__((cleanup(_defer_cleanup_block))) ATTR_UNUSED _defer_block_t _DEFER_CONCAT(_defer_var_, \
                                                                                                __COUNTER__) = ^

/* ============================================================
 * C / MSVC — Structured Exception Handling __try/__finally
 * ============================================================
 *
 * The __finally block is guaranteed to execute whenever the associated
 * __try block exits, regardless of return, break, exception, or fall-through.
 * No special compiler flags are required.
 *
 * Syntax differs slightly: the user's block immediately follows 'defer':
 *   defer { cleanup(); };   ← trailing semicolon required (MSVC)
 */
#elif defined(_MSC_VER)

    #define defer \
        __try {   \
        } __finally

#else
    #error "defer.h: unsupported compiler. Supported: GCC 4.9+, Clang (with -fblocks), MSVC, any C++ compiler."
#endif

// ================= DEFER WRAPPERS==============================================
/**
 *
 * @brief Pre-built RAII cleanup wrappers built on top of defer.
 *
 * This header provides ready-to-use scope-exit macros for the most common
 * resource types. Each macro expands to a 'defer' block that performs the
 * appropriate cleanup when the enclosing scope exits.
 *
 * To suppress inclusion of specific wrapper groups, define the corresponding
 * opt-out macro before including this header:
 * @code
 *   #define DEFER_NO_PTHREAD      // omit pthread_mutex wrappers
 *   #define DEFER_NO_POSIX_FD    // omit POSIX file-descriptor wrappers
 *   #define DEFER_NO_POSIX_MMAP  // omit mmap wrapper
 *   #include <solidc/defer.h>
 * @endcode
 *
 * @section platform Platform notes
 *
 * Wrappers are enabled per-platform using feature-detection macros:
 *
 *  - POSIX wrappers (defer_close, defer_mmap_unmap, defer_unlock,
 *    defer_rwlock_*) require a POSIX-conforming environment. They are
 *    omitted automatically on Windows / MSVC unless _POSIX_C_SOURCE is set.
 *
 *  - Windows-specific wrappers (defer_CloseHandle, defer_LocalFree,
 *    defer_VirtualFree) are compiled only when _WIN32 is defined.
 *
 *  - defer_fclose and defer_free are universally available (C standard only).
 *
 * @section syntax Syntax reminder
 *
 * All wrappers follow the same pattern:
 * @code
 *   resource_t *r = acquire_resource();
 *   defer_free(r);            // cleanup registered; runs at scope exit
 *
 * @endcode
 *
 * @warning Do NOT use 'return', 'break', 'goto', or 'continue' inside a
 *          deferred block. The behaviour is undefined in all backends.
 */

/*=======================================================================================
 * On Clang, blocks capture variables by value. To allow a deferred block
 * to write back to the original variable (e.g. to NULL it after free),
 * the variable must be declared with __block storage.
 *
 * Use DEFER_VAR to declare pointer variables that will be cleaned up by
 * a nulling wrapper (defer_free, defer_fclose, defer_close, etc.).
 *
 * On GCC and C++, DEFER_VAR is a no-op — nested functions and lambdas
 * already see the original variable directly.
 *
 * Example:
 *   DEFER_VAR char *buf = malloc(256);
 *   defer_free(buf);   // buf is reliably NULL'd on scope exit on all backends
 *================================================================================================*/

/* =========================================================================
 * §1  Platform detection
 * =========================================================================
 *
 * DEFER_POSIX  — set when a POSIX environment is available.
 * DEFER_WIN32  — set when targeting Win32.
 */
#if defined(_WIN32) || defined(_WIN64)
    #define DEFER_WIN32 1
#else
    #if defined(__unix__) || defined(__unix) || (defined(__APPLE__) && defined(__MACH__))
        #define DEFER_POSIX 1
    #elif defined(_POSIX_VERSION)
        #define DEFER_POSIX 1
    #endif
#endif

/* =========================================================================
 * §2  Universal wrappers — C standard library only
 *     Available on every platform and compiler.
 * ========================================================================= */

#include <stdio.h>  /* fclose() */
#include <stdlib.h> /* free()   */

/**
 * @brief Free a malloc'd pointer at scope exit.
 *
 * The pointer is cast to void* so that const-qualified pointers (e.g.
 * char *const) do not produce -Wcast-qual diagnostics. The variable is
 * set to NULL after freeing to catch use-after-free in debug builds.
 *
 * @param ptr An lvalue of any pointer type previously returned by
 *            malloc / calloc / realloc / strdup.
 *
 * Example:
 * @code
 *   char *buf = malloc(256);
 *   defer_free(buf);
 * @endcode
 */
#define defer_free(ptr)     \
    defer {                 \
        free((void*)(ptr)); \
        (ptr) = NULL;       \
    }

/**
 * @brief Close a FILE* at scope exit (NULL-safe).
 *
 * Calls fclose() only when the pointer is non-NULL. The variable is set
 * to NULL afterward so that a second fclose() cannot occur if the macro
 * is somehow invoked more than once (defensive coding).
 *
 * @param f A FILE* previously returned by fopen / fdopen / tmpfile.
 *
 * Example:
 * @code
 *   FILE *f = fopen("data.bin", "rb");
 *   if (!f) { return -1; }
 *   defer_fclose(f);
 * @endcode
 */
#define defer_fclose(f)  \
    defer {              \
        if ((f)) {       \
            fclose((f)); \
            (f) = NULL;  \
        }                \
    }

/**
 * @brief Execute a nullary function pointer at scope exit.
 *
 * Useful for teardown callbacks registered at runtime, or for any
 * cleanup that does not require a resource handle.
 *
 * @param fn A function pointer with signature void (*)(void).
 *
 * Example:
 * @code
 *   defer_call(shutdown_subsystem);
 * @endcode
 */
#define defer_call(fn) \
    defer { (fn)(); }

/**
 * @brief Execute a function pointer with a single void* argument at scope exit.
 *
 * Mirrors the cleanup-callback signature used by pthread_cleanup_push,
 * atexit-style handlers, and many C library destroy functions.
 *
 * @param fn  A function pointer with signature void (*)(void *).
 * @param arg The argument passed to fn.
 *
 * Example:
 * @code
 *   defer_call1(EVP_MD_CTX_free, mdctx);
 * @endcode
 */
#define defer_call1(fn, arg) \
    defer { (fn)((arg)); }

/**
 * @brief Restore a variable to a saved value at scope exit.
 *
 * Useful for temporarily overriding errno, global flags, signal masks,
 * or any scalar that must be restored on all exit paths.
 *
 * @param var       An lvalue whose type supports assignment.
 * @param saved_val The value to restore; evaluated at declaration time.
 *
 * Example:
 * @code
 *   int saved_errno = errno;
 *   defer_restore(errno, saved_errno);
 *
 *   // ... code that may clobber errno ...
 * @endcode
 */
#define defer_restore(var, saved_val) \
    defer { (var) = (saved_val); }

/* =========================================================================
 * §3  POSIX wrappers
 *     Compiled only in POSIX-conforming environments.
 * ========================================================================= */

#if defined(DEFER_POSIX)

    /* -----------------------------------------------------------------------
     * §3.1  File descriptors
     * ----------------------------------------------------------------------- */
    #ifndef DEFER_NO_POSIX_FD

        #include <unistd.h> /* close() */

        /**
         * @brief Close a POSIX file descriptor at scope exit.
         *
         * Skips close() for invalid descriptors (-1). Sets the variable to -1
         * after closing to prevent double-close bugs.
         *
         * @param fd An int lvalue holding a valid open file descriptor,
         *           or -1 (in which case no action is taken).
         *
         * Example:
         * @code
         *   int fd = open("data.bin", O_RDONLY);
         *   if (fd < 0) { return -1; }
         *   defer_close(fd);
         * @endcode
         */
        #define defer_close(fd)  \
            defer {              \
                if ((fd) >= 0) { \
                    close(fd);   \
                    (fd) = -1;   \
                }                \
            }

    #endif /* DEFER_NO_POSIX_FD */

    /* -----------------------------------------------------------------------
     * §3.2  mmap regions
     * ----------------------------------------------------------------------- */
    #ifndef DEFER_NO_POSIX_MMAP

        #include <sys/mman.h> /* munmap() */

        /**
         * @brief Unmap an mmap'd region at scope exit.
         *
         * Calls munmap() only when ptr is not MAP_FAILED and len is non-zero.
         *
         * @param ptr A void* returned by mmap().
         * @param len The mapping length in bytes, as passed to mmap().
         *
         * Example:
         * @code
         *   void *map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
         *   if (map == MAP_FAILED) { return -1; }
         *   defer_munmap(map, len);
         * @endcode
         */
        #define defer_munmap(ptr, len)                  \
            defer {                                     \
                if ((ptr) != MAP_FAILED && (len) > 0) { \
                    munmap((ptr), (len));               \
                    (ptr) = MAP_FAILED;                 \
                }                                       \
            }

    #endif /* DEFER_NO_POSIX_MMAP */

    /* -----------------------------------------------------------------------
     * §3.3  pthreads — mutexes and rwlocks
     * ----------------------------------------------------------------------- */
    #ifndef DEFER_NO_PTHREAD

        #include <pthread.h> /* pthread_mutex_unlock, pthread_rwlock_unlock */

        /**
         * @brief Unlock a pthread mutex at scope exit.
         *
         * The mutex must already be locked by the calling thread at the point
         * this macro is declared. The unlock happens unconditionally on exit.
         *
         * @param mu A pthread_mutex_t lvalue (not a pointer).
         *
         * Example:
         * @code
         *   pthread_mutex_lock(&ctx->mu);
         *   defer_mutex_unlock(ctx->mu);
         *
         *   // ... critical section ...
         * @endcode
         */
        #define defer_mutex_unlock(mu) \
            defer { pthread_mutex_unlock(&(mu)); }

        /**
         * @brief Release a pthread read-write lock at scope exit.
         *
         * Use after pthread_rwlock_rdlock() or pthread_rwlock_wrlock().
         * Calls pthread_rwlock_unlock() unconditionally on scope exit.
         *
         * @param rw A pthread_rwlock_t lvalue (not a pointer).
         *
         * Example:
         * @code
         *   pthread_rwlock_rdlock(&table->rw);
         *   defer_rwlock_unlock(table->rw);
         * @endcode
         */
        #define defer_rwlock_unlock(rw) \
            defer { pthread_rwlock_unlock(&(rw)); }

    #endif /* DEFER_NO_PTHREAD */

    /* -----------------------------------------------------------------------
     * §3.4  DIR* (opendir / closedir)
     * ----------------------------------------------------------------------- */

    #include <dirent.h> /* DIR, closedir() */

    /**
     * @brief Close a DIR* at scope exit (NULL-safe).
     *
     * @param d A DIR* previously returned by opendir() or fdopendir().
     *
     * Example:
     * @code
     *   DIR *d = opendir("/tmp");
     *   if (!d) { return -1; }
     *   defer_closedir(d);
     * @endcode
     */
    #define defer_closedir(d)  \
        defer {                \
            if ((d)) {         \
                closedir((d)); \
                (d) = NULL;    \
            }                  \
        }

#endif /* DEFER_POSIX */

/* =========================================================================
 * §4  Windows-specific wrappers
 *     Compiled only when targeting Win32 / Win64.
 * ========================================================================= */

#if defined(DEFER_WIN32)

    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include "platform.h" /* HANDLE, CloseHandle, LocalFree, VirtualFree */

    /**
     * @brief Close a Win32 HANDLE at scope exit.
     *
     * Skips CloseHandle() for INVALID_HANDLE_VALUE and NULL. Sets the
     * variable to INVALID_HANDLE_VALUE after closing.
     *
     * @param h A HANDLE lvalue (file, event, thread, process, etc.).
     *
     * Example:
     * @code
     *   HANDLE h = CreateFile(...);
     *   if (h == INVALID_HANDLE_VALUE) { return -1; }
     *   defer_CloseHandle(h);
     * @endcode
     */
    #define defer_CloseHandle(h)                      \
        defer {                                       \
            if ((h) && (h) != INVALID_HANDLE_VALUE) { \
                CloseHandle(h);                       \
                (h) = INVALID_HANDLE_VALUE;           \
            }                                         \
        }

    /**
     * @brief Free a pointer allocated by LocalAlloc / LocalReAlloc at scope exit.
     *
     * @param p An HLOCAL (or LPVOID) previously returned by LocalAlloc.
     *
     * Example:
     * @code
     *   LPWSTR msg = NULL;
     *   FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | ..., ..., &msg, ...);
     *   defer_LocalFree(msg);
     * @endcode
     */
    #define defer_LocalFree(p)  \
        defer {                 \
            if ((p)) {          \
                LocalFree((p)); \
                (p) = NULL;     \
            }                   \
        }

    /**
     * @brief Release a VirtualAlloc'd region at scope exit.
     *
     * Calls VirtualFree with MEM_RELEASE (dwSize must be 0 per the API
     * contract when using MEM_RELEASE).
     *
     * @param p A LPVOID previously returned by VirtualAlloc.
     *
     * Example:
     * @code
     *   LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
     *   if (!mem) { return -1; }
     *   defer_VirtualFree(mem);
     * @endcode
     */
    #define defer_VirtualFree(p)                  \
        defer {                                   \
            if ((p)) {                            \
                VirtualFree((p), 0, MEM_RELEASE); \
                (p) = NULL;                       \
            }                                     \
        }

    /**
     * @brief Unmap a view of a file mapping at scope exit.
     *
     * Calls UnmapViewOfFile(); NULL-safe.
     *
     * @param view A LPVOID returned by MapViewOfFile().
     *
     * Example:
     * @code
     *   LPVOID view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
     *   if (!view) { return -1; }
     *   defer_UnmapViewOfFile(view);
     * @endcode
     */
    #define defer_UnmapViewOfFile(view)  \
        defer {                          \
            if ((view)) {                \
                UnmapViewOfFile((view)); \
                (view) = NULL;           \
            }                            \
        }

#endif /* DEFER_WIN32 */

#ifdef DEFER_AUTOFREE
    /* =========================================================================
     * §5  autofree — automatic free() on scope exit
     *
     * Attaches a free() cleanup to a pointer variable so that it is freed
     * automatically when it goes out of scope. Analogous to GLib's g_autoptr
     * but restricted to malloc-family pointers (use defer_fclose / defer_close
     * for FILE* and file descriptors).
     *
     * Usage:
     *   autofree char *buf = malloc(256);
     *   autofree my_struct_t *obj = my_struct_create();
     *   // Both are freed at scope exit — no manual free() needed.
     *
     * The macro is a declaration specifier, not a statement. Place it at the
     * start of a pointer declaration. The variable must be a pointer type;
     * applying autofree to a non-pointer produces a compile-time error.
     *
     * Platform support:
     *   GCC 4.9+   — __attribute__((cleanup)) on the declared variable.
     *   Clang      — same; __block not required because cleanup fires on the
     *                variable directly, not inside a captured block.
     *   MSVC       — not supported; the macro expands to nothing and emits a
     *                #pragma message. Use defer_free() on MSVC instead.
     *   C++        — not supported; use RAII types (std::unique_ptr) instead.
     *                The macro expands to nothing with a diagnostic.
     * ========================================================================= */

    #if defined(__cplusplus)
        /* C++: direct free() on a raw pointer is almost always wrong; push the
         * caller toward std::unique_ptr or a custom deleter. */
        #pragma message("autofree is a no-op in C++; use std::unique_ptr instead.")
        #define autofree /* nothing */

    #elif defined(_MSC_VER)
        /* MSVC does not implement __attribute__((cleanup)). */
        #pragma message("autofree is a no-op on MSVC; use defer_free() instead.")
        #define autofree /* nothing */
    #else                /* GCC or Clang in C mode */

/**
 * @brief Cleanup handler invoked by __attribute__((cleanup)) when an
 *        autofree-decorated pointer goes out of scope.
 *
 * @param ptr Pointer to the pointer variable being cleaned up.
 *            The value is cast to void** so the function accepts any
 *            pointer type without -Wincompatible-pointer-types warnings.
 */
static inline void _autofree_cleanup(void* ptr) {
    /* ptr is &variable, so dereference to get the actual heap pointer. */
    void* heap_ptr = *(void**)ptr;
    if (heap_ptr) {
        free(heap_ptr);
        heap_ptr = NULL;
    }
}

        #define autofree __attribute__((cleanup(_autofree_cleanup)))

    #endif /* compiler dispatch */
#endif

#endif /* DEFER_H */