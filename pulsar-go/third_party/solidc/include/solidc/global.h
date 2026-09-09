/**
 * @file global.h
 * @brief Global variable management and DLL export definitions.
 */

#ifndef SOLIDC_GLOBAL_H
#define SOLIDC_GLOBAL_H

#if defined(_WIN32) || defined(__CYGWIN__)
    #ifdef SOLIDC_EXPORTS
        #define SOLIDC_API __declspec(dllexport)
    #else
        #define SOLIDC_API __declspec(dllimport)
    #endif
#else
    #define SOLIDC_API __attribute__((visibility("default")))
#endif

#endif /* SOLIDC_GLOBAL_H */
