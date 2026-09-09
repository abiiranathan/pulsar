#include "../include/thread.h"

#include <limits.h>
#include <stddef.h>  // for NULL
#include <stdio.h>   // for perror, fprintf
#include <stdlib.h>  // for malloc, free
#include <string.h>  // for strerror
#include <time.h>    // for nanosleep

#ifdef _WIN32
    #include <process.h>  // for Windows threading
#else
    #include <sys/syscall.h>  // for syscall numbers
#endif

/* Platform-specific error code handling */
#ifdef _WIN32
    /** Maximum Windows error code we'll handle (prevents overflow). */
    #define MAX_WIN_ERROR 0x7FFFFFFF

/**
 * Converts Windows error code to portable error code.
 * @param win_error Windows error code from GetLastError().
 * @return Portable error code (truncated if necessary).
 */
static inline int win_error_to_errno(DWORD win_error) {
    // Prevent overflow when converting to int
    if (win_error > MAX_WIN_ERROR) {
        return EINVAL;  // Use generic error for out-of-range values
    }
    // Map common Windows errors to POSIX equivalents where sensible
    switch (win_error) {
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:
            return ENOMEM;
        case ERROR_INVALID_PARAMETER:
        case ERROR_INVALID_HANDLE:
            return EINVAL;
        case ERROR_ACCESS_DENIED:
            return EACCES;
        default:
            return (int)win_error;
    }
}

/**
 * Validates a Windows thread handle.
 * @param handle Thread handle to validate.
 * @return 1 if valid, 0 if invalid.
 */
static inline int is_valid_thread_handle(HANDLE handle) { return (handle != NULL && handle != INVALID_HANDLE_VALUE); }
#endif

/* Windows-specific thread parameter wrapper */
#ifdef _WIN32
/** Internal structure to pass parameters to Windows thread start wrapper. */
typedef struct {
    ThreadStartRoutine start_routine; /**< User's thread start function. */
    void* data;                       /**< User's thread argument. */
    void* result;                     /**< Thread return value storage. */
    volatile int started;             /**< Flag indicating thread has started. */
} ThreadParams;

/**
 * Internal Windows thread start wrapper.
 * Converts between Windows WINAPI calling convention and our generic interface.
 * @param lpParameter Pointer to ThreadParams structure.
 * @return Thread exit code as DWORD (always 0, actual result stored in params).
 */
DWORD WINAPI thread_start_wrapper(LPVOID lpParameter) {
    if (lpParameter == NULL) {
        return 1;  // Indicate error
    }

    ThreadParams* params = (ThreadParams*)lpParameter;
    ThreadStartRoutine start_routine = params->start_routine;
    void* data = params->data;

    // Signal that we've started and captured our parameters
    params->started = 1;

    if (start_routine == NULL) {
        params->result = NULL;
        return 1;  // Indicate error
    }

    // Execute user's thread function and store result
    params->result = start_routine(data);

    // We don't free params here - it must live until thread_join or thread_detach
    return 0;  // Success
}
#endif

int thread_create(Thread* thread, ThreadStartRoutine start_routine, void* data) {
    if (thread == NULL || start_routine == NULL) {
        return EINVAL;
    }

#ifdef _WIN32
    ThreadParams* params = (ThreadParams*)malloc(sizeof(ThreadParams));
    if (params == NULL) {
        return ENOMEM;
    }

    params->start_routine = start_routine;
    params->data = data;
    params->result = NULL;
    params->started = 0;

    HANDLE handle = CreateThread(NULL,                  // Security attributes (default)
                                 0,                     // Stack size (default)
                                 thread_start_wrapper,  // Thread start function
                                 params,                // Thread parameter
                                 0,                     // Creation flags (run immediately)
                                 NULL                   // Thread ID (not needed)
    );

    if (!is_valid_thread_handle(handle)) {
        int error = win_error_to_errno(GetLastError());
        free(params);
        return error;
    }

    // Wait briefly for thread to capture parameters
    // This prevents a race where the thread hasn't started yet
    for (int i = 0; i < 1000 && !params->started; i++) {
        Sleep(0);  // Yield to allow thread to start
    }

    *thread = handle;
    return 0;

#else  // POSIX
    int ret = pthread_create(thread, NULL, start_routine, data);
    return ret;
#endif
}

int thread_create_attr(Thread* thread, ThreadAttr* attr, ThreadStartRoutine start_routine, void* data) {
    if (thread == NULL || attr == NULL || start_routine == NULL) {
        return EINVAL;
    }

#ifdef _WIN32
    ThreadParams* params = (ThreadParams*)malloc(sizeof(ThreadParams));
    if (params == NULL) {
        return ENOMEM;
    }

    params->start_routine = start_routine;
    params->data = data;
    params->result = NULL;
    params->started = 0;

    HANDLE handle = CreateThread(&attr->sa,             // Security attributes
                                 attr->stackSize,       // Stack size
                                 thread_start_wrapper,  // Thread start function
                                 params,                // Thread parameter
                                 0,                     // Creation flags (run immediately)
                                 NULL                   // Thread ID (not needed)
    );

    if (!is_valid_thread_handle(handle)) {
        int error = win_error_to_errno(GetLastError());
        free(params);
        return error;
    }

    // Wait briefly for thread to capture parameters
    for (int i = 0; i < 1000 && !params->started; i++) {
        Sleep(0);  // Yield to allow thread to start
    }

    *thread = handle;
    return 0;

#else  // POSIX
    int ret = pthread_create(thread, attr, start_routine, data);
    return ret;
#endif
}

int thread_join(Thread tid, void** retval) {
#ifdef _WIN32
    if (!is_valid_thread_handle(tid)) {
        return EINVAL;
    }

    DWORD wait_result = WaitForSingleObject(tid, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        return win_error_to_errno(GetLastError());
    }

    // Retrieve the thread's parameters to get the actual return value
    // We stored the ThreadParams pointer in thread-local storage conceptually,
    // but since we can't access it directly, we need a different approach.
    //
    // LIMITATION: On Windows, we cannot reliably retrieve the void* return value
    // after the thread has exited without additional infrastructure (like storing
    // ThreadParams in a global map). For now, we can only return the DWORD exit code.

    if (retval != NULL) {
        DWORD exit_code;
        if (GetExitCodeThread(tid, &exit_code)) {
            // Note: This loses information if the original return value was a 64-bit pointer
            // This is a fundamental limitation of mapping POSIX thread API to Windows
            *retval = (void*)(uintptr_t)exit_code;
        } else {
            *retval = NULL;
            // Continue anyway - we successfully waited
        }
    }

    CloseHandle(tid);
    return 0;

#else  // POSIX
    int ret = pthread_join(tid, retval);
    return ret;
#endif
}

/**
 * Terminates the calling thread and returns a value to the caller.
 * @param retval The return value for the thread. On POSIX, this is a void pointer.
 *               On Windows, this should be cast from a DWORD exit code.
 * @note On Windows, only the lower 32 bits of the pointer are used as the exit code.
 * @note This function does not return.
 */
void thread_exit(void* retval) {
#ifdef _WIN32
    // Cast pointer to DWORD (typically only lower 32 bits are meaningful on Windows)
    ExitThread((DWORD)(uintptr_t)retval);
#else
    pthread_exit(retval);
#endif
}

int thread_detach(Thread tid) {
#ifdef _WIN32
    if (!is_valid_thread_handle(tid)) {
        return EINVAL;
    }

    // On Windows, "detaching" means we close our reference to the handle.
    // The thread continues to run, and the system will clean up when it exits.
    //
    // CRITICAL DIFFERENCE FROM POSIX: After this call, the thread handle
    // becomes invalid and cannot be used for any operations, including join.
    // This matches POSIX semantics where you cannot join a detached thread.

    if (!CloseHandle(tid)) {
        return win_error_to_errno(GetLastError());
    }
    return 0;

#else  // POSIX
    int ret = pthread_detach(tid);
    return ret;
#endif
}

#ifdef _WIN32
DWORD thread_self() { return GetCurrentThreadId(); }
#else
pthread_t thread_self() { return pthread_self(); }
#endif

/* Thread Attribute Management */

int thread_attr_init(ThreadAttr* attr) {
    if (attr == NULL) {
        return EINVAL;
    }

#ifdef _WIN32
    // Initialize to safe defaults with explicit zeroing for security
    memset(attr, 0, sizeof(ThreadAttr));
    attr->stackSize = 0;  // Use system default stack size
    attr->sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    attr->sa.lpSecurityDescriptor = NULL;  // Default security
    attr->sa.bInheritHandle = FALSE;       // Don't inherit handles by default
    return 0;

#else  // POSIX
    int ret = pthread_attr_init(attr);
    return ret;
#endif
}

int thread_attr_destroy(ThreadAttr* attr) {
    if (attr == NULL) {
        return EINVAL;
    }

#ifdef _WIN32
    // Explicitly zero out the structure for security
    memset(attr, 0, sizeof(ThreadAttr));
    return 0;

#else  // POSIX
    int ret = pthread_attr_destroy(attr);
    return ret;
#endif
}

/* Utility Functions */

void sleep_ms(int ms) {
    if (ms <= 0) {
        return;
    }

#ifdef _WIN32
    // Sleep takes DWORD; INT_MAX always fits, so no further range check needed.
    Sleep((DWORD)ms);

#else  // POSIX
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;

    // Handle EINTR by continuing to sleep for remaining time
    struct timespec remaining;
    while (nanosleep(&ts, &remaining) == -1) {
        if (errno != EINTR) {
            break;
        }
        ts = remaining;
    }
#endif
}

int get_pid() {
#ifdef _WIN32
    DWORD pid = GetCurrentProcessId();
    // Validate that PID fits in int (should always be true)
    if (pid > INT_MAX) {
        return -1;  // Indicate error
    }
    return (int)pid;
#else  // POSIX
    return (int)getpid();
#endif
}

unsigned long get_tid() {
#ifdef _WIN32
    return (unsigned long)GetCurrentThreadId();
#elif defined(__linux__)
    /*
     * Kernel thread ID: unique system-wide, matches `ps -T`/`htop` output,
     * and stable across runs.  Casting pthread_self() instead would expose
     * the glibc thread descriptor address, which is neither unique
     * system-wide nor meaningful between processes.
     */
    return (unsigned long)syscall(SYS_gettid);
#else  // POSIX fallback
    // Note: pthread_t is an opaque type and may not be an integer.
    // Casting to unsigned long is not portable but commonly works.
    return (unsigned long)pthread_self();
#endif
}

long get_ncpus() {
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    DWORD count = sysinfo.dwNumberOfProcessors;

    // Validate that the count fits in a long and is reasonable
    if (count == 0 || count > LONG_MAX) {
        return -1;  // Indicate error
    }
    return (long)count;

#else  // POSIX
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    // sysconf returns -1 on error, pass it through
    return ncpus;
#endif
}

/* Platform-specific System Information Functions */

#ifdef _WIN32

/**
 * Gets parent process ID using Windows toolhelp API.
 * @return Parent process ID, or -1 on error.
 */
int get_ppid() {
    HANDLE snapshot;
    PROCESSENTRY32 pe32;
    DWORD current_pid = GetCurrentProcessId();
    DWORD parent_pid = (DWORD)-1;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return -1;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return -1;
    }

    do {
        if (pe32.th32ProcessID == current_pid) {
            parent_pid = pe32.th32ParentProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);

    if (parent_pid == (DWORD)-1 || parent_pid > INT_MAX) {
        return -1;
    }
    return (int)parent_pid;
}

/**
 * Gets current user's Security Identifier (SID) - Windows equivalent of UID.
 * @return User SID as unsigned int (hash of actual SID), or (unsigned int)-1 on error.
 * @note Returns a hash of the user's SID since Windows SIDs are variable-length.
 */
unsigned int get_uid() {
    HANDLE token = NULL;
    DWORD token_info_length = 0;
    TOKEN_USER* token_user = NULL;
    unsigned int uid_hash = (unsigned int)-1;

    // Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return (unsigned int)-1;
    }

    // Get required buffer size
    GetTokenInformation(token, TokenUser, NULL, 0, &token_info_length);
    if (token_info_length == 0) {
        CloseHandle(token);
        return (unsigned int)-1;
    }

    token_user = (TOKEN_USER*)malloc(token_info_length);
    if (token_user == NULL) {
        CloseHandle(token);
        return (unsigned int)-1;
    }

    // Get user SID
    if (!GetTokenInformation(token, TokenUser, token_user, token_info_length, &token_info_length)) {
        free(token_user);
        CloseHandle(token);
        return (unsigned int)-1;
    }

    // Create a simple hash of the SID for a numeric identifier
    PSID sid = token_user->User.Sid;
    if (IsValidSid(sid)) {
        DWORD sid_length = GetLengthSid(sid);
        BYTE* sid_bytes = (BYTE*)sid;

        // Simple FNV-1a hash
        uid_hash = 2166136261u;
        for (DWORD i = 0; i < sid_length; i++) {
            uid_hash ^= sid_bytes[i];
            uid_hash *= 16777619u;
        }
    }

    free(token_user);
    CloseHandle(token);
    return uid_hash;
}

/**
 * Gets primary group SID - Windows equivalent of GID.
 * @return Group SID as unsigned int (hash of actual SID), or (unsigned int)-1 on error.
 * @note Returns a hash of the primary group's SID.
 */
unsigned int get_gid() {
    HANDLE token = NULL;
    DWORD token_info_length = 0;
    TOKEN_PRIMARY_GROUP* primary_group = NULL;
    unsigned int gid_hash = (unsigned int)-1;

    // Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return (unsigned int)-1;
    }

    // Get required buffer size
    GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &token_info_length);
    if (token_info_length == 0) {
        CloseHandle(token);
        return (unsigned int)-1;
    }

    primary_group = (TOKEN_PRIMARY_GROUP*)malloc(token_info_length);
    if (primary_group == NULL) {
        CloseHandle(token);
        return (unsigned int)-1;
    }

    // Get primary group SID
    if (!GetTokenInformation(token, TokenPrimaryGroup, primary_group, token_info_length, &token_info_length)) {
        free(primary_group);
        CloseHandle(token);
        return (unsigned int)-1;
    }

    // Create a simple hash of the SID
    PSID sid = primary_group->PrimaryGroup;
    if (IsValidSid(sid)) {
        DWORD sid_length = GetLengthSid(sid);
        BYTE* sid_bytes = (BYTE*)sid;

        // Simple FNV-1a hash
        gid_hash = 2166136261u;
        for (DWORD i = 0; i < sid_length; i++) {
            gid_hash ^= sid_bytes[i];
            gid_hash *= 16777619u;
        }
    }

    free(primary_group);
    CloseHandle(token);
    return gid_hash;
}

/** Static buffer for Windows username. Not thread-safe by design (matches POSIX behavior). */
static char win_username_buffer[UNLEN + 1];

/**
 * Gets current user's name.
 * @return Pointer to static string containing username, or NULL on error.
 * @note Not thread-safe - uses static buffer (matches POSIX getpwuid behavior).
 */
char* get_username() {
    DWORD username_len = UNLEN + 1;

    if (!GetUserNameA(win_username_buffer, &username_len)) {
        return NULL;
    }

    return win_username_buffer;
}

/** Static buffer for Windows group name. Not thread-safe by design (matches POSIX behavior). */
static char win_groupname_buffer[256];

/**
 * Gets current user's primary group name.
 * @return Pointer to static string containing group name, or NULL on error.
 * @note Not thread-safe - uses static buffer (matches POSIX getgrgid behavior).
 * @note On Windows, this returns the name of the user's primary group from their token.
 */
char* get_groupname() {
    HANDLE token = NULL;
    DWORD token_info_length = 0;
    TOKEN_PRIMARY_GROUP* primary_group = NULL;
    char* result = NULL;

    // Open current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return NULL;
    }

    // Get required buffer size for primary group
    GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &token_info_length);
    if (token_info_length == 0) {
        CloseHandle(token);
        return NULL;
    }

    primary_group = (TOKEN_PRIMARY_GROUP*)malloc(token_info_length);
    if (primary_group == NULL) {
        CloseHandle(token);
        return NULL;
    }

    // Get primary group SID
    if (!GetTokenInformation(token, TokenPrimaryGroup, primary_group, token_info_length, &token_info_length)) {
        free(primary_group);
        CloseHandle(token);
        return NULL;
    }

    // Lookup account name from SID
    DWORD name_len = sizeof(win_groupname_buffer);
    DWORD domain_len = 0;
    SID_NAME_USE sid_type;

    // First call to get domain length
    LookupAccountSidA(NULL, primary_group->PrimaryGroup, win_groupname_buffer, &name_len, NULL, &domain_len, &sid_type);

    if (domain_len > 0) {
        char* domain_buffer = (char*)malloc(domain_len);
        if (domain_buffer != NULL) {
            name_len = sizeof(win_groupname_buffer);
            if (LookupAccountSidA(NULL, primary_group->PrimaryGroup, win_groupname_buffer, &name_len, domain_buffer,
                                  &domain_len, &sid_type)) {
                result = win_groupname_buffer;
            }
            free(domain_buffer);
        }
    }

    free(primary_group);
    CloseHandle(token);
    return result;
}

#else  // POSIX

int get_ppid() {
    pid_t ppid = getppid();
    // POSIX guarantees ppid fits in int, but be defensive
    if (ppid < 0 || ppid > INT_MAX) {
        return -1;
    }
    return (int)ppid;
}

unsigned int get_uid() { return (unsigned int)getuid(); }

unsigned int get_gid() { return (unsigned int)getgid(); }

char* get_username() {
    struct passwd* pw = getpwuid(getuid());
    if (pw == NULL) {
        return NULL;  // Don't call perror - not thread-safe
    }
    // Return pointer to static data - documented as not thread-safe
    return pw->pw_name;
}

char* get_groupname() {
    struct group* gr = getgrgid(getgid());
    if (gr == NULL) {
        return NULL;  // Don't call perror - not thread-safe
    }

    // Return pointer to static data - documented as not thread-safe
    return gr->gr_name;
}

#endif  // _WIN32
