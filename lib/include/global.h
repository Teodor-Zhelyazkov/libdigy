#pragma once

#define TRUE 1
#define FALSE 0

// debug mode - unlocks logging
#define DEBUG FALSE

#define DNS_BUFFER_SIZE 4096
#define DNS_PORT 53

// Max resolvers length
#define DNS_RESOLVERS_LEN 8
// define opt edns rr type integer
#define OPT_EDNS_RR_TYPE 41


#if defined __STDC_VERSION__
    #if (__STDC_VERSION__ == 202000) || (__STDC_VERSION__ >= 202311L)
        // Temporary C2x placeholder or official C23 standard
        #define THREAD_LOCAL thread_local
    #elif (__STDC_VERSION__ == 201710L) || (__STDC_VERSION__ == 201112L)
        // C17 or C11 standards
        #define THREAD_LOCAL _Thread_local
    #elif (__STDC_VERSION__ == 199901L)
        // C99 standard on Linux (GCC / Clang extension)
        #define THREAD_LOCAL __thread
    #else
        // Fallback for older or undocumented versions on Linux
        #define THREAD_LOCAL __thread
    #endif
#else
    // Fallback if __STDC_VERSION__ is missing but compiling on Linux (GCC/Clang)
    #define THREAD_LOCAL __thread
#endif