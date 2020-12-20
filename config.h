#ifndef __CONFIG_H_
#define __CONFIG_H_

/*
 * This is the default path where the driver will look for the
 * default tracefiles. You can override it at runtime with the -t flag.
 */
#define TRACEDIR "/course/cs0330/pub/malloc/traces/"

/*
 * This is the list of default tracefiles in TRACEDIR that the driver
 * will use for testing. Modify this if you want to add or delete
 * traces from the driver's test suite.
 */
#define BASE_TRACEFILES                                                  \
    "amptjp-bal.rep", "cccp-bal.rep", "cp-decl-bal.rep", "expr-bal.rep", \
        "random-bal.rep", "random2-bal.rep", "binary-bal.rep",           \
        "binary2-bal.rep"

#define COALESCE_TRACEFILES "coalescing-bal.rep", "coalescing2-bal.rep"

#define REALLOC_TRACEFILES "realloc-bal.rep", "realloc2-bal.rep"

typedef struct trace_baseline_t {
    const char *name; /* trace name */
    const int consistent;
    const double min_util; /* baseline min_util to pass */
} trace_baseline_t;
static const trace_baseline_t trace_baseline_table[] = {
    {"amptjp-bal.rep", 1, 0.0},      {"cccp-bal.rep", 1, 0.0},
    {"cp-decl-bal.rep", 1, 0.0},     {"expr-bal.rep", 1, 0.0},
    {"random-bal.rep", 1, 0.0},      {"random2-bal.rep", 1, 0.0},
    {"binary-bal.rep", 1, 0.0},      {"binary2-bal.rep", 1, 0.0},
    {"coalescing-bal.rep", 1, 0.90}, {"coalescing2-bal.rep", 1, 0.90},
    {"realloc-bal.rep", 1, 0.45},    {"realloc2-bal.rep", 1, 0.45}};
/*
 * This constant gives the estimated performance of the libc malloc
 * package using our traces on some reference system, typically the
 * same kind of system the students use. Its purpose is to cap the
 * contribution of throughput to the performance index. Once the
 * students surpass the AVG_LIBC_THRUPUT, they get no further benefit
 * to their score.  This deters students from building extremely fast,
 * but extremely stupid malloc packages.
 */
#define AVG_LIBC_THRUPUT 600E3 /* 600 Kops/sec */

/*
 * This constant determines the contributions of space utilization
 * (UTIL_WEIGHT) and throughput (1 - UTIL_WEIGHT) to the performance
 * index.
 */
#define UTIL_WEIGHT .80

/*
 * Alignment requirement in bytes (either 4 or 8)
 */
#define ALIGNMENT 8

/*
 * Maximum heap size in bytes
 */
#define MAX_HEAP (20 * (1 << 20)) /* 20 MB */

/*****************************************************************************
 * Set exactly one of these USE_xxx constants to "1" to select a timing method
 *****************************************************************************/
#define USE_FCYC 0   /* cycle counter w/K-best scheme (x86 & Alpha only) */
#define USE_ITIMER 0 /* interval timer (any Unix box) */
#define USE_GETTOD 1 /* gettimeofday (any Unix box) */

#endif
