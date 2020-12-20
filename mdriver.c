#include <assert.h>
#include <errno.h>
#include <float.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "fsecs.h"
#include "memlib.h"
#include "mm.h"
#include "mminline.h"

/**********************
 * Constants and macros
 **********************/

/* Misc */
#define MAXLINE 1024       /* max string size */
#define MAX_REPL_SIZE 1024 /* max string size */
#define HDRLINES 4         /* number of header lines in a trace file */
#define LINENUM(i)                                            \
    (i + 5) /* cnvt trace request nums to linenums (origin 1) \
             */

/* Returns true if p is ALIGNMENT-byte aligned */
#define IS_ALIGNED(p) ((((unsigned long)(p)) % ALIGNMENT) == 0)

/******************************
 * The key compound data types
 *****************************/

/* Records the extent of each block's payload */
typedef struct range_t {
    char *lo;             /* low payload address */
    char *hi;             /* high payload address */
    struct range_t *next; /* next list element */
} range_t;

/* Characterizes a single trace operation (allocator request) */
typedef struct {
    enum { ALLOC, FREE, REALLOC } type; /* type of request */
    int index;                          /* index for free() to use later */
    int size;                           /* byte size of alloc/realloc request */
} traceop_t;

/* Holds the information for one trace file*/
typedef struct {
    char trace_name[1024];
    int sugg_heapsize;   /* suggested heap size (unused) */
    int num_ids;         /* number of alloc/realloc ids */
    int num_ops;         /* number of distinct requests */
    int weight;          /* weight for this trace (unused) */
    traceop_t *ops;      /* array of requests */
    char **blocks;       /* array of ptrs returned by malloc/realloc... */
    size_t *block_sizes; /* ... and a corresponding array of payload sizes */
} trace_t;

/*
 * Holds the params to the xxx_speed functions, which are timed by fcyc.
 * This struct is necessary because fcyc accepts only a pointer array
 * as input.
 */
typedef struct {
    trace_t *trace;
    range_t *ranges;
} speed_t;

/* Summarizes the important stats for some malloc function on some trace */
typedef struct {
    /* defined for both libc malloc and student malloc package (mm.c) */
    double ops;  /* number of ops (malloc/free/realloc) in the trace */
    int valid;   /* was the trace processed correctly by the allocator? */
    double secs; /* number of secs needed to run the trace */

    char trace_name[1024];

    /* defined only for the student malloc package */
    double util; /* space utilization for this trace (always 0 for libc) */

    /* Note: secs and util are only defined if valid is true */
} stats_t;

/********************
 * Global variables
 *******************/
int verbose = 0;       /* global flag for verbose output */
static int errors = 0; /* number of errs found when running student malloc */
char msg[MAXLINE + 100];     /* for whenever we need to compose an error message */

/* Directory where default tracefiles are found */
static char tracedir[MAXLINE] = TRACEDIR;

/* The filenames of the default tracefiles */
static char *default_tracefiles[] = {DEFAULT_TRACEFILES, NULL};

/*********************
 * Function prototypes
 *********************/

/* these functions manipulate range lists */
static int add_range(range_t **ranges, char *lo, int size, int tracenum,
                     int opnum);
static void remove_range(range_t **ranges, char *lo);
static void clear_ranges(range_t **ranges);

/* These functions read, allocate, and free storage for traces */
static trace_t *read_trace(char *tracedir, char *filename);
static void free_trace(trace_t *trace);

/* Routines for evaluating the correctness and speed of libc malloc */
static int eval_libc_valid(trace_t *trace, int tracenum);
static void eval_libc_speed(void *ptr);

/* Routines for evaluating correctnes, space utilization, and speed
   of the student's malloc package in mm.c */
static int eval_mm_valid(trace_t *trace, int tracenum, range_t **ranges);
static double eval_mm_util(trace_t *trace, int tracenum, range_t **ranges);
static void eval_mm_speed(void *ptr);

/* Various helper routines */
static double compute_performance_index(int num_tracefiles, double secs,
                                        double ops, double util);
static void printresults(int n, stats_t *stats);
static void printpassed(int n, stats_t *stats);
static void printresultsgradescope(int n, stats_t *stats);

static void usage(void);
static void unix_error(char *msg);
static void malloc_error(int tracenum, int opnum, char *msg);
static void app_error(char *msg);
static void driver();
/**************
 * Main routine
 **************/
int main(int argc, char **argv) {
    int i;
    char c;
    char **tracefiles = NULL;   /* null-terminated array of trace file names */
    int num_tracefiles = 0;     /* the number of traces in that array */
    trace_t *trace = NULL;      /* stores a single trace file in memory */
    range_t *ranges = NULL;     /* keeps track of block extents for one trace */
    stats_t *libc_stats = NULL; /* libc stats for each trace */
    stats_t *mm_stats = NULL;   /* mm (i.e. student) stats for each trace */
    speed_t speed_params;       /* input parameters to the xx_speed routines */

    int run_libc = 0;   /* If set, run libc malloc (set by -l) */
    int autograder = 0; /* If set, emit summary info for autograder (-g) */
    int gradescope = 0;
    /* temporaries used to compute the performance index */
    double secs, ops, util, perfindex;
    int numcorrect;

    /*
     * Read and interpret the command line arguments
     */

    while ((c = getopt(argc, argv, "f:t:hvVgGalr")) != EOF) {
        switch (c) {
            case 'r': /* start repl */
                driver();
                return 0;
            case 'g': /* Generate summary info for the autograder */
                autograder = 1;
                break;
            case 'G':
                gradescope = 1;
                break;
            case 'f': /* Use one specific trace file only (relative to curr dir)
                       */
                num_tracefiles = 1;
                if (verbose == 0) {
                    verbose = 1;
                }
                if ((tracefiles = realloc(tracefiles, 2 * sizeof(char *))) ==
                    NULL)
                    unix_error("ERROR: realloc failed in main");
                strcpy(tracedir, "");
                tracefiles[0] = strdup(optarg);
                tracefiles[1] = NULL;
                break;
            case 't': /* Directory where the traces are located */
                if (num_tracefiles == 1) /* ignore if -f already encountered */
                    break;
                strcpy(tracedir, optarg);
                if (tracedir[strlen(tracedir) - 1] != '/')
                    strcat(tracedir, "/"); /* path always ends with "/" */
                break;
            case 'l': /* Run libc malloc */
                run_libc = 1;
                break;
            case 'v': /* verbose mode -v */
                verbose = 1;
                break;
            case 'V': /* Be more verbose than -v */
                verbose = 2;
                break;
            case 'h': /* Print this message */
                usage();
                exit(0);
            default:
                usage();
                exit(1);
        }
    }

    /*
     * If no -f command line arg, then use the entire set of tracefiles
     * defined in default_traces[]
     */
    if (tracefiles == NULL) {
        tracefiles = default_tracefiles;
        num_tracefiles = sizeof(default_tracefiles) / sizeof(char *) - 1;
        if (!gradescope) {
            printf("Using default tracefiles in %s\n", tracedir);
        }
    }

    /* Initialize the timing package */
    init_fsecs();

    /*
     * Optionally run and evaluate the libc malloc package
     */
    if (run_libc) {
        if (verbose > 1) printf("\nTesting libc malloc\n");

        /* Allocate libc stats array, with one stats_t struct per tracefile */
        libc_stats = (stats_t *)calloc(num_tracefiles, sizeof(stats_t));
        if (libc_stats == NULL) unix_error("libc_stats calloc in main failed");

        /* Evaluate the libc malloc package using the K-best scheme */
        for (i = 0; i < num_tracefiles; i++) {
            trace = read_trace(tracedir, tracefiles[i]);
            libc_stats[i].ops = trace->num_ops;
            if (verbose > 1) printf("Checking libc malloc for correctness, ");
            libc_stats[i].valid = eval_libc_valid(trace, i);
            if (libc_stats[i].valid) {
                speed_params.trace = trace;
                if (verbose > 1) printf("and performance.\n");
                libc_stats[i].secs = fsecs(eval_libc_speed, &speed_params);
            }
            free_trace(trace);
        }

        /* Display the libc results in a compact table */
        if (verbose) {
            printf("\nResults for libc malloc:\n");
            printresults(num_tracefiles, libc_stats);
        }
    }

    /*
     * Always run and evaluate the student's mm package
     */
    if (verbose > 1) printf("\nTesting mm malloc\n");

    /* Allocate the mm stats array, with one stats_t struct per tracefile */
    mm_stats = (stats_t *)calloc(num_tracefiles, sizeof(stats_t));
    if (mm_stats == NULL) unix_error("mm_stats calloc in main failed");

    /* Initialize the simulated memory system in memlib.c */
    mem_init();

    /* Evaluate student's mm malloc package using the K-best scheme */
    for (i = 0; i < num_tracefiles; i++) {
        trace = read_trace(tracedir, tracefiles[i]);
        strncpy(mm_stats[i].trace_name, trace->trace_name, MAXLINE);
        mm_stats[i].ops = trace->num_ops;
        if (verbose > 1) printf("Checking mm_malloc for correctness, ");
        mm_stats[i].valid = eval_mm_valid(trace, i, &ranges);
        if (mm_stats[i].valid) {
            if (verbose > 1) printf("efficiency, ");
            mm_stats[i].util = eval_mm_util(trace, i, &ranges);
            speed_params.trace = trace;
            speed_params.ranges = ranges;
            if (verbose > 1) printf("and performance.\n");
            mm_stats[i].secs = fsecs(eval_mm_speed, &speed_params);
        }
        free_trace(trace);
    }

    /* Display the mm results in a compact table */
    if (verbose) {
        printf("\nResults for mm malloc:\n");
        printresults(num_tracefiles, mm_stats);
        printf("\n");
    }

    if (gradescope) {
        printresultsgradescope(num_tracefiles, mm_stats);
    } else if (verbose == 0) {
        printpassed(num_tracefiles, mm_stats);
    }

    /*
     * Accumulate the aggregate statistics for the student's mm package
     */
    secs = 0;
    ops = 0;
    util = 0;
    numcorrect = 0;
    for (i = 0; i < num_tracefiles; i++) {
        secs += mm_stats[i].secs;
        ops += mm_stats[i].ops;
        util += mm_stats[i].util;
        if (mm_stats[i].valid) numcorrect++;
    }

    perfindex = compute_performance_index(num_tracefiles, secs, ops, util);

    // if (verbose == 0) {
    //     printpassed(num_tracefiles,mm_stats);
    // }
    if (errors != 0) { /* There were errors */
        perfindex = 0.0;
        printf("Terminated with %d errors\n", errors);
    }

    if (autograder) {
        printf("correct:%d\n", numcorrect);
        printf("perfidx:%.0f\n", perfindex);
    }

    exit(0);
}

/*****************************************************************
 * The following routines manipulate the range list, which keeps
 * track of the extent of every allocated block payload. We use the
 * range list to detect any overlapping allocated blocks.
 ****************************************************************/

/*
 * add_range - As directed by request opnum in trace tracenum,
 *     we've just called the student's mm_malloc to allocate a block of
 *     size bytes at addr lo. After checking the block for correctness,
 *     we create a range struct for this block and add it to the range list.
 */
static int add_range(range_t **ranges, char *lo, int size, int tracenum,
                     int opnum) {
    char *hi = lo + size - 1;
    range_t *p;
    char msg[MAXLINE];

    assert(size > 0);

    /* Payload addresses must be ALIGNMENT-byte aligned */
    if (!IS_ALIGNED(lo)) {
        sprintf(msg, "Payload address (%p) not aligned to %d bytes", lo,
                ALIGNMENT);
        malloc_error(tracenum, opnum, msg);
        return 0;
    }

    /* The payload must lie within the extent of the heap */
    if ((lo < (char *)mem_heap_lo()) || (lo > (char *)mem_heap_hi()) ||
        (hi < (char *)mem_heap_lo()) || (hi > (char *)mem_heap_hi())) {
        sprintf(msg, "Payload (%p:%p) lies outside heap (%p:%p)", lo, hi,
                mem_heap_lo(), mem_heap_hi());
        malloc_error(tracenum, opnum, msg);
        return 0;
    }

    /* The payload must not overlap any other payloads */
    for (p = *ranges; p != NULL; p = p->next) {
        if ((lo >= p->lo && lo <= p->hi) || (hi >= p->lo && hi <= p->hi)) {
            sprintf(msg, "Payload (%p:%p) overlaps another payload (%p:%p)\n",
                    lo, hi, p->lo, p->hi);
            malloc_error(tracenum, opnum, msg);
            return 0;
        }
    }

    /*
     * Everything looks OK, so remember the extent of this block
     * by creating a range struct and adding it the range list.
     */
    if ((p = (range_t *)malloc(sizeof(range_t))) == NULL)
        unix_error("malloc error in add_range");
    p->next = *ranges;
    p->lo = lo;
    p->hi = hi;
    *ranges = p;
    return 1;
}

/*
 * remove_range - Free the range record of block whose payload starts at lo
 */
static void remove_range(range_t **ranges, char *lo) {
    range_t *p;
    range_t **prevpp = ranges;

    for (p = *ranges; p != NULL; p = p->next) {
        if (p->lo == lo) {
            *prevpp = p->next;
            free(p);
            break;
        }
        prevpp = &(p->next);
    }
}

/*
 * clear_ranges - free all of the range records for a trace
 */
static void clear_ranges(range_t **ranges) {
    range_t *p;
    range_t *pnext;

    for (p = *ranges; p != NULL; p = pnext) {
        pnext = p->next;
        free(p);
    }
    *ranges = NULL;
}

void _check(int errcode) {
    if (errcode < 0) {
        printf("Error: %s\n", strerror(-errcode));
    }
}

/**********************************************
 * The following routines manipulate tracefiles
 *********************************************/

/*
 * read_trace - read a trace file and store it in memory
 */
static trace_t *read_trace(char *tracedir, char *filename) {

  FILE *tracefile;
  trace_t *trace;
  char type[MAXLINE];
  char path[MAXLINE];
  unsigned index, size;
  unsigned max_index = 0;
  unsigned op_index;

  if (verbose > 1) printf("Reading tracefile: %s\n", filename);

  /* Allocate the trace record */
  if ((trace = (trace_t *)malloc(sizeof(trace_t))) == NULL)
    unix_error("malloc 1 failed in read_trance");

  /* Read the trace file header */
  strcpy(path, tracedir);
  strcat(path, filename);
  strncpy(trace->trace_name, filename, MAXLINE - 1);
  if ((tracefile = fopen(path, "r")) == NULL) {
    sprintf(msg, "Could not open %s in read_trace", path);
    unix_error(msg);
  }
  _check(fscanf(tracefile, "%d", &(trace->sugg_heapsize))); /* not used */
  _check(fscanf(tracefile, "%d", &(trace->num_ids)));
  _check(fscanf(tracefile, "%d", &(trace->num_ops)));
  _check(fscanf(tracefile, "%d", &(trace->weight))); /* not used */

  /* We'll store each request line in the trace in this array */
  if ((trace->ops = (traceop_t *)malloc(trace->num_ops * sizeof(traceop_t))) ==
      NULL)
    unix_error("malloc 2 failed in read_trace");

  /* We'll keep an array of pointers to the allocated blocks here... */
  if ((trace->blocks = (char **)malloc(trace->num_ids * sizeof(char *))) ==
      NULL)
    unix_error("malloc 3 failed in read_trace");

  /* ... along with the corresponding byte sizes of each block */
  if ((trace->block_sizes =
           (size_t *)malloc(trace->num_ids * sizeof(size_t))) == NULL)
    unix_error("malloc 4 failed in read_trace");

  /* read every request line in the trace file */
  index = 0;
  op_index = 0;
  while (fscanf(tracefile, "%s", type) != EOF) {
    switch (type[0]) {
      case 'a':
        _check(fscanf(tracefile, "%u %u", &index, &size));
        trace->ops[op_index].type = ALLOC;
        trace->ops[op_index].index = index;
        trace->ops[op_index].size = size;
        max_index = (index > max_index) ? index : max_index;
        break;
      case 'r':
        _check(fscanf(tracefile, "%u %u", &index, &size));
        trace->ops[op_index].type = REALLOC;
        trace->ops[op_index].index = index;
        trace->ops[op_index].size = size;
        max_index = (index > max_index) ? index : max_index;
        break;
      case 'f':
        _check(fscanf(tracefile, "%ud", &index));
        trace->ops[op_index].type = FREE;
        trace->ops[op_index].index = index;
        break;
      default:
        printf("Bogus type character (%c) in tracefile %s\n", type[0], path);
        exit(1);
    }
    op_index++;
  }
    fclose(tracefile);
    assert((int)max_index == trace->num_ids - 1);
    assert((int)op_index == trace->num_ops);

    return trace;
}

/*
 * free_trace - Free the trace record and the three arrays it points
 *              to, all of which were allocated in read_trace().
 */
void free_trace(trace_t *trace) {
    free(trace->ops); /* free the three arrays... */
    free(trace->blocks);
    free(trace->block_sizes);
    free(trace); /* and the trace record itself... */
}

/**********************************************************************
 * The following functions evaluate the correctness, space utilization,
 * and throughput of the libc and mm malloc packages.
 **********************************************************************/

/*
 * eval_mm_valid - Check the mm malloc package for correctness
 */
static int eval_mm_valid(trace_t *trace, int tracenum, range_t **ranges) {
    int i, j;
    int index;
    int size;
    int oldsize;
    char *newp;
    char *oldp;
    char *p;

    /* Reset the heap and free any records in the range list */
    mem_reset_brk();
    clear_ranges(ranges);

    /* Call the mm package's init function */
    if (mm_init() < 0) {
        malloc_error(tracenum, 0, "mm_init failed.");
        return 0;
    }

    /* Interpret each operation in the trace in order */
    for (i = 0; i < trace->num_ops; i++) {
        index = trace->ops[i].index;
        size = trace->ops[i].size;

        switch (trace->ops[i].type) {
            case ALLOC: /* mm_malloc */

                /* Call the student's malloc */
                if ((p = mm_malloc(size)) == NULL) {
                    malloc_error(tracenum, i, "mm_malloc failed.");
                    return 0;
                }

                /*
                 * Test the range of the new block for correctness and add it
                 * to the range list if OK. The block must be  be aligned
                 * properly, and must not overlap any currently allocated block.
                 */
                if (add_range(ranges, p, size, tracenum, i) == 0) return 0;

                /* ADDED: cgw
                 * fill range with low byte of index.  This will be used later
                 * if we realloc the block and wish to make sure that the old
                 * data was copied to the new block
                 */
                memset(p, index & 0xFF, size);

                /* Remember region */
                trace->blocks[index] = p;
                trace->block_sizes[index] = size;
                break;

            case REALLOC: /* mm_realloc */

                /* Call the student's realloc */
                oldp = trace->blocks[index];
                if ((newp = mm_realloc(oldp, size)) == NULL) {
                    malloc_error(tracenum, i, "mm_realloc failed.");
                    return 0;
                }

                /* Remove the old region from the range list */
                remove_range(ranges, oldp);

                /* Check new block for correctness and add it to range list */
                if (add_range(ranges, newp, size, tracenum, i) == 0) return 0;

                /* ADDED: cgw
                 * Make sure that the new block contains the data from the old
                 * block and then fill in the new block with the low order byte
                 * of the new index
                 */
                oldsize = trace->block_sizes[index];
                if (size < oldsize) oldsize = size;
                for (j = 0; j < oldsize; j++) {
                    if (newp[j] != (index & 0xFF)) {
                        malloc_error(tracenum, i,
                                     "mm_realloc did not preserve the "
                                     "data from old block");
                        return 0;
                    }
                }
                memset(newp, index & 0xFF, size);

                /* Remember region */
                trace->blocks[index] = newp;
                trace->block_sizes[index] = size;
                break;

            case FREE: /* mm_free */

                /* Remove region from list and call student's free function */
                p = trace->blocks[index];
                remove_range(ranges, p);
                mm_free(p);
                break;

            default:
                app_error("Nonexistent request type in eval_mm_valid");
        }
    }

    /* As far as we know, this is a valid malloc package */
    return 1;
}

/*
 * eval_mm_util - Evaluate the space utilization of the student's package
 *   The idea is to remember the high water mark "hwm" of the heap for
 *   an optimal allocator, i.e., no gaps and no internal fragmentation.
 *   Utilization is the ratio hwm/heapsize, where heapsize is the
 *   size of the heap in bytes after running the student's malloc
 *   package on the trace. Note that our implementation of mem_sbrk()
 *   doesn't allow the students to decrement the brk pointer, so brk
 *   is always the high water mark of the heap.
 *
 */
static double eval_mm_util(trace_t *trace, int tracenum, range_t **ranges) {
    assert((int)tracenum || 1);
    assert((long)ranges || 1);

    int i;
    int index;
    int size, newsize, oldsize;
    int max_total_size = 0;
    int total_size = 0;
    char *p;
    char *newp, *oldp;

    /* initialize the heap and the mm malloc package */
    mem_reset_brk();
    clear_ranges(ranges);
    if (mm_init() < 0) app_error("mm_init failed in eval_mm_util");
    for (i = 0; i < trace->num_ops; i++) {
        index = trace->ops[i].index;
        size = trace->ops[i].size;

        switch (trace->ops[i].type) {
            case ALLOC: /* mm_alloc */
                index = trace->ops[i].index;
                size = trace->ops[i].size;

                if ((p = mm_malloc(size)) == NULL)
                    app_error("mm_malloc failed in eval_mm_util");

                /* Still need to memset, because otherwise there's no guarantee
                 * the space is usable */
                if (add_range(ranges, p, size, tracenum, i) == 0) return 0;
                memset(p, index & 0xFF, size);

                /* Remember region and size */
                trace->blocks[index] = p;
                trace->block_sizes[index] = size;

                /* Keep track of current total size
                 * of all allocated blocks */
                total_size += size;

                /* Update statistics */
                max_total_size =
                    (total_size > max_total_size) ? total_size : max_total_size;
                break;

            case REALLOC: /* mm_realloc */
                index = trace->ops[i].index;
                newsize = trace->ops[i].size;
                oldsize = trace->block_sizes[index];

                oldp = trace->blocks[index];
                if ((newp = mm_realloc(oldp, newsize)) == NULL)
                    app_error("mm_realloc failed in eval_mm_util");

                /* Still need to memset and check region integrity */
                remove_range(ranges, oldp);

                if (add_range(ranges, newp, size, tracenum, i) == 0) return 0;

                memset(newp, index & 0xFF, size);

                /* Remember region and size */
                oldsize = trace->block_sizes[index];
                trace->blocks[index] = newp;
                trace->block_sizes[index] = newsize;

                /* Keep track of current total size
                 * of all allocated blocks */
                total_size += (newsize - oldsize);

                /* Update statistics */
                max_total_size =
                    (total_size > max_total_size) ? total_size : max_total_size;
                break;

            case FREE: /* mm_free */
                index = trace->ops[i].index;
                size = trace->block_sizes[index];
                p = trace->blocks[index];
                remove_range(ranges, p);

                mm_free(p);

                /* Keep track of current total size
                 * of all allocated blocks */
                total_size -= size;

                break;

            default:
                app_error("Nonexistent request type in eval_mm_util");
        }
    }

    return ((double)max_total_size / (double)mem_heapsize());
}

/*
 * eval_mm_speed - This is the function that is used by fcyc()
 *    to measure the running time of the mm malloc package.
 */
static void eval_mm_speed(void *ptr) {
    int i, index, size, newsize;
    char *p, *newp, *oldp, *block;
    trace_t *trace = ((speed_t *)ptr)->trace;

    /* Reset the heap and initialize the mm package */
    mem_reset_brk();
    if (mm_init() < 0) app_error("mm_init failed in eval_mm_speed");

    /* Interpret each trace request */
    for (i = 0; i < trace->num_ops; i++) {
        index = trace->ops[i].index;
        size = trace->ops[i].size;
        switch (trace->ops[i].type) {
            case ALLOC: /* mm_malloc */
                index = trace->ops[i].index;
                size = trace->ops[i].size;
                if ((p = mm_malloc(size)) == NULL)
                    app_error("mm_malloc error in eval_mm_speed");
                memset(p, index & 0xFF, size);
                trace->blocks[index] = p;
                break;

            case REALLOC: /* mm_realloc */
                index = trace->ops[i].index;
                newsize = trace->ops[i].size;
                oldp = trace->blocks[index];
                if ((newp = mm_realloc(oldp, newsize)) == NULL)
                    app_error("mm_realloc error in eval_mm_speed");
                memset(newp, index & 0xFF, size);
                trace->blocks[index] = newp;
                break;

            case FREE: /* mm_free */
                index = trace->ops[i].index;
                block = trace->blocks[index];
                mm_free(block);
                break;

            default:
                app_error("Nonexistent request type in eval_mm_valid");
        }
    }
}

/*
 * eval_libc_valid - We run this function to make sure that the
 *    libc malloc can run to completion on the set of traces.
 *    We'll be conservative and terminate if any libc malloc call fails.
 *
 */
static int eval_libc_valid(trace_t *trace, int tracenum) {
    int i, newsize;
    char *p, *newp, *oldp;

    for (i = 0; i < trace->num_ops; i++) {
        switch (trace->ops[i].type) {
            case ALLOC: /* malloc */
                if ((p = malloc(trace->ops[i].size)) == NULL) {
                    malloc_error(tracenum, i, "libc malloc failed");
                    unix_error("System message");
                }
                trace->blocks[trace->ops[i].index] = p;
                break;

            case REALLOC: /* realloc */
                newsize = trace->ops[i].size;
                oldp = trace->blocks[trace->ops[i].index];
                if ((newp = realloc(oldp, newsize)) == NULL) {
                    malloc_error(tracenum, i, "libc realloc failed");
                    unix_error("System message");
                }
                trace->blocks[trace->ops[i].index] = newp;
                break;

            case FREE: /* free */
                free(trace->blocks[trace->ops[i].index]);
                break;

            default:
                app_error("invalid operation type  in eval_libc_valid");
        }
    }

    return 1;
}

/*
 * eval_libc_speed - This is the function that is used by fcyc() to
 *    measure the running time of the libc malloc package on the set
 *    of traces.
 */
static void eval_libc_speed(void *ptr) {
    int i;
    int index, size, newsize;
    char *p, *newp, *oldp, *block;
    trace_t *trace = ((speed_t *)ptr)->trace;

    for (i = 0; i < trace->num_ops; i++) {
        switch (trace->ops[i].type) {
            case ALLOC: /* malloc */
                index = trace->ops[i].index;
                size = trace->ops[i].size;
                if ((p = malloc(size)) == NULL)
                    unix_error("malloc failed in eval_libc_speed");
                trace->blocks[index] = p;
                break;

            case REALLOC: /* realloc */
                index = trace->ops[i].index;
                newsize = trace->ops[i].size;
                oldp = trace->blocks[index];
                if ((newp = realloc(oldp, newsize)) == NULL)
                    unix_error("realloc failed in eval_libc_speed\n");

                trace->blocks[index] = newp;
                break;

            case FREE: /* free */
                index = trace->ops[i].index;
                block = trace->blocks[index];
                free(block);
                break;
        }
    }
}

/*************************************
 * Some miscellaneous helper routines
 ************************************/

/*
 * compute_performance_index - computes a score based on the weighted sum of
 * utilization and throughput
 */
static double compute_performance_index(int num_tracefiles, double secs,
                                        double ops, double util) {
    double avg_util = util / num_tracefiles;
    double avg_throughput = ops / secs;

    double throughput_score;
    if (avg_throughput > AVG_LIBC_THRUPUT) {
        throughput_score = 1.0;
    } else {
        throughput_score = avg_throughput / AVG_LIBC_THRUPUT;
    }

    printf(
        "Computing performance index from average util %f and throughput score "
        "%f\n",
        avg_util * 100, throughput_score * 100);
    return 100 *
           ((avg_util * UTIL_WEIGHT) + (1.0 - UTIL_WEIGHT) * throughput_score);
}

/*
 * printresults - prints a performance summary for some malloc package
 */
static void printresults(int n, stats_t *stats) {
    int i;
    double secs = 0;
    double ops = 0;
    double util = 0;

    /* Print the individual results for each trace */
    printf("%6s %4s                %12s %6s%5s%8s%11s\n", "trace#", " name",
           " consistent", "util", "ops", "secs", "Kops");
    printf(
        "----------------------------------------------------------------------"
        "-"
        "\n");
    for (i = 0; i < n; i++) {
        if (stats[i].valid) {
            printf(" %-2d     %-19s   %-9s%5.1f%%%8.0f%10.6f%8.0f\n", i,
                   stats[i].trace_name, "yes", stats[i].util * 100.0,
                   stats[i].ops, stats[i].secs,
                   (stats[i].ops / 1e3) / stats[i].secs);
            secs += stats[i].secs;
            ops += stats[i].ops;
            util += stats[i].util;
        } else {
            printf(" %-2d     %-19s   %-7s%6s%6s%7s%11s\n", i,
                   stats[i].trace_name, "no", "-", "-", "-", "-");
        }
    }
    /* Print the aggregate results for the set of traces */

    if (errors == 0) {
        printf("%24s%10.1f%%%8.0f%10.6f%8.0f\n",
               "Total                             ", (util / n) * 100.0, ops,
               secs, (ops / 1e3) / secs);
    } else {
        printf("%12s%30s%6s%7s%11s\n", "Total        ", "-", "-", "-", "-");
    }
}

static void printresultsgradescope(int n, stats_t *stats) {
    int i;
    double util = 0;
    /* Print the results for grading purpose */
    for (i = 0; i < n; i++) {
        if (stats[i].valid) {
            printf(" %-2d     %-9s%5.0f\n", i,

                   "yes", stats[i].util * 100.0);
            util += stats[i].util;
        } else {
            printf(" %-2d      %-7s%6s\n", i,

                   "no", "-");
        }
    }

    /* Print the aggregate results for the set of traces */
    if (errors == 0) {
        printf("%24s%10.0f\n", "Total                      ",
               (util / n) * 100.0);
    } else {
        printf("%12s%30s%6s%7s%11s\n", "Total        ", "-", "-", "-", "-");
    }
}

/*
 * printresults - prints a performance summary for some malloc package
 */
static void printpassed(int n, stats_t *stats) {
    int i;
    printf("\n");
    char *passed_failed[] = {"\x1B[31mFAILED\x1B[0m", "\x1B[32mPASSED\x1B[0m"};

    /* Print the individual results for each trace */
    printf("%6s %4s                %12s %6s%10s\n", "trace#", " name",
           " consistent", "util", "passed?");
    printf(
        "----------------------------------------------------------------------"
        "-"
        "\n");
    for (i = 0; i < n; i++) {
        for (int j = 0; j < 12; ++j) {
            if (!strcmp(stats[i].trace_name, trace_baseline_table[j].name)) {
                if (stats[i].valid) {
                    int passed = 0;
                    if (stats[i].util >= trace_baseline_table[j].min_util) {
                        passed = 1;
                    }

                    printf(" %-2d     %-19s   %-9s%5.1f%20s\n", i,
                           stats[i].trace_name, "yes", stats[i].util * 100.0,
                           passed_failed[passed]);
                } else {
                    printf(" %-2d     %-19s   %-7s%6s%21s\n", i,
                           stats[i].trace_name, "no", "-", passed_failed[0]);
                }
            }
        }
    }
    printf("\n");
}

/*
 * app_error - Report an arbitrary application error
 */
void app_error(char *msg) {
    printf("%s\n", msg);
    exit(1);
}

/*
 * unix_error - Report a Unix-style error
 */
void unix_error(char *msg) {
    printf("%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * malloc_error - Report an error returned by the mm_malloc package
 */
void malloc_error(int tracenum, int opnum, char *msg) {
    errors++;
    int ret = fprintf(stderr, "ERROR [trace %d, line %d]: %s\n", tracenum,
                      LINENUM(opnum), msg);
    (void)(ret);  // suppress unused result warnings
}

/*
 * usage - Explain the command line arguments
 */
static void usage(void) {
    fprintf(stderr, "Usage: mdriver [-hvValr] [-f <file>] [-t <dir>]\n");
    fprintf(stderr, "Options\n");
    fprintf(stderr, "\t-f <file>  Use <file> as the trace file.\n");
    fprintf(stderr, "\t-g         Generate summary info for autograder.\n");
    fprintf(stderr, "\t-r         Open the malloc REPL.\n");
    fprintf(stderr, "\t-G         Grade summary info for gradescope.\n");
    fprintf(stderr, "\t-h         Print this message.\n");
    fprintf(stderr, "\t-l         Run libc malloc as well.\n");
    fprintf(stderr, "\t-t <dir>   Directory to find default traces.\n");
    fprintf(stderr, "\t-v         Print per-trace performance breakdowns.\n");
    fprintf(stderr, "\t-V         Print additional debug info.\n");
    fprintf(stderr, "\t-p         activates repl\n");
}

// REPL Code
typedef struct rpl_block {
    char is_valid;
    char *ptr;   /* ptr returned by malloc/realloc... */
    size_t size; /* ... and a corresponding payload size */
    int index;
} repl_block_t;

typedef struct repl_state {
    range_t *ranges;
    size_t prologue_size;
    size_t epilogue_size;
    block_t *heap_start;
    int tracenum;
    int num_ops;
    int num_blocks;
    repl_block_t blocks[];
} repl_t;

/* instantiates the REPL with a given number of blocks*/
repl_t *make_repl_state(size_t num_blocks) {
    repl_t *ret;
    if ((ret = (void *)malloc(sizeof(repl_t) +
                              num_blocks * sizeof(repl_block_t))) == NULL) {
        unix_error("System failed to initialize REPL");
    }
    ret->ranges = NULL;
    ret->tracenum = 0;
    ret->num_ops = 0;
    ret->num_blocks = num_blocks;

    // initialize all the repl blocks
    for (int i = 0; i < ret->num_blocks; ++i) {
        ret->blocks[i].is_valid = 0;
        ret->blocks[i].ptr = NULL;
        ret->blocks[i].size = 0;
        ret->blocks[i].index = i;
    }
    return ret;
}

repl_t *repl_state;

/* given a pointer to a block, finds the repl block
 * that contains it  */
repl_block_t *find_repl_block_from_block(char *block_ptr, repl_block_t blocks[],
                                         int repl_size) {
    for (int i = 0; i < repl_size; ++i) {
        if ((blocks[i].ptr - 8) == block_ptr) {
            return &blocks[i];
        }
    }
    return (repl_block_t *)NULL;
}

/*
 * prints the state of the heap
 * arguments: none
 * returns: nothing
 */
void mm_print_heap_repl(repl_block_t blocks[], int repl_size) {
    // prints heap data & prologue
    block_t *heap_start = (block_t *)mem_heap_lo();
    printf("heap size: %d\n", (int)mem_heapsize());
    block_t *b = (block_t *)heap_start;
    printf("prologue \t\tblock at %p \tsize %d\n", (void *)heap_start,
           (int)block_size(heap_start));
    b = block_next(b);

    block_t *epilogue = (block_t *)((char *)mem_heap_hi() - TAGS_SIZE + 1);
    // prints all blocks
    while (b != epilogue) {
        int index = -1;

        // if we are a valid repl block
        repl_block_t *repl =
            find_repl_block_from_block((char *)(b), blocks, repl_size);
        if (repl != NULL) {
            index = repl->index;
        }

        // stores the identifying '[index]' after a repl block
        // if it's a valid repl block
        char indexstr[10] = "";
        if (index != -1) sprintf(indexstr, "[%d]", index);

        if (block_allocated(b)) {
            printf("block%s allocated \tblock at %p \tsize %d\n", indexstr,
                   (void *)(b), (int)block_size(b));
        } else {
            printf("free block \t\tblock at %p \tsize %d \tNext: %p\n",
                   (void *)(b), (int)block_size(b),
                   (void *)(block_next_free(b)));
        }
        size_t s1 = block_size(b);
        size_t s2 = block_end_size(b);
        if (s1 != s2) {
            printf("block%s at %p had differing size tags: %d and %d\n\n",
                   indexstr, (void *)b, (int)s1, (int)s2);
        }
        if (s1 < MINBLOCKSIZE) {
            printf("block%s at %p had too small a size: %d\n\n", indexstr,
                   (void *)b, (int)s1);
        }
        if (block_next(b) > epilogue + MINBLOCKSIZE) {
            printf("next block wasn't in the heap. \n\n");
        }
        b = block_next(b);
    }
    printf("epilogue \t\tblock at %p \tsize %d\n\n\n", (void *)(epilogue),
           (int)block_size(epilogue));
    // return 0;
}

void help_cmd(const char *msg) {
    if (msg == NULL) {
        printf("msg is null\n");
    }
    fprintf(stderr, "commands:\n");
    fprintf(stderr,
            "malloc <index> <size>  \t mallocs the block at <index> to a size "
            "<amount>\n");
    fprintf(stderr,
            "realloc <index> <size> \t reallocs the block at <index> to "
            "<amount>\n");
    fprintf(stderr, "free <index>           \t frees block at <index>\n");
    // fprintf(stderr, "reset                  \t resets memory\n");
    fprintf(
        stderr,
        "check_heap             \t calls mm_check_heap() to test validity\n");
    fprintf(stderr, "print                  \t prints the heap\n");
    // fprintf(stderr, " print -f              \t prints the free list \n");
    fprintf(
        stderr,
        "print -b <index>      \t prints the status of the block at <index>\n");
    fprintf(stderr, "quit                   \t quits repl\n");
}

void print_cmd(const char *msg) {
    if (msg == NULL) {
        printf("msg is null\n");
    }

    // print block info
    int index;
    if ((sscanf(msg, "p -b %d", &index) == 1) ||
        (sscanf(msg, "print -b %d", &index) == 1)) {
        if ((index < 0) || (index >= repl_state->num_blocks)) {
            printf("ERROR: index must be between 0 and %d\n",
                   repl_state->num_blocks);
            return;
        }
        if (!repl_state->blocks[index].is_valid) {
            printf("block[%d] is not allocated\n", index);
            return;
        }

        block_t *b = (block_t *)(repl_state->blocks[index].ptr - 8);
        if (block_allocated(b)) {
            printf("block[%d] allocated \tblock at %p \tsize %d\n", index,
                   (void *)(b), (int)block_size(b));
        }
        return;
    }
    // print free list

    // print heap (default)
    mm_print_heap_repl(repl_state->blocks, MAX_REPL_SIZE);
}

void check_heap_cmd(const char *msg) {
    if (msg == NULL) {
        printf("msg is null\n");
    }
    mm_check_heap();
}

void reset_cmd(const char *msg) {
    if (msg == NULL) {
        printf("msg is null\n");
    }
    mem_reset_brk();
    clear_ranges(&(repl_state->ranges));

    /* Call the mm package's init function */
    if (mm_init() < 0) {
        malloc_error(repl_state->tracenum, 0, "mm_init failed.");
        exit(1);
    }
    repl_state->tracenum++;
    repl_state->num_ops = 0;
    // repl_state->prologue_size = (size_t) (((char*)flist_first) -
    // (char*)mem_heap_lo());
    // char* p = mm_malloc(1);
    // repl_state->heap_start = payload_to_block(p);
    // repl_state->epilogue_size = (size_t) ((char*)mem_heap_hi() -
    // (char*)block_next(payload_to_block(p)));
}

void quit_cmd(const char *msg) {
    if (msg == NULL) {
        printf("msg is null\n");
    }
    // strcmp(msg,"quit");
    mem_reset_brk();
    clear_ranges(&(repl_state->ranges));
    free(repl_state);
    exit(0);
}

void malloc_cmd(const char *msg) {
    int index, size;
    char *p;
    if ((sscanf(msg, "m %d %d", &index, &size) != 2) &&
        (sscanf(msg, "malloc %d %d", &index, &size) != 2)) {
        printf("%s\n", "usage: malloc <index> <amount>");
        return;
    }
    if ((index < 0) || (index >= repl_state->num_blocks)) {
        printf("ERROR: index must be between 0 and %d\n",
               repl_state->num_blocks);
        return;
    }
    if (repl_state->blocks[index].is_valid) {
        printf("ERROR: index already in use\n");
        return;
    }
    repl_state->num_ops++;
    if ((p = mm_malloc(size)) == NULL) {
        malloc_error(repl_state->tracenum, repl_state->num_ops,
                     "mm_malloc failed.");
        return;
    }

    /*
     * Test the range of the new block for correctness and add it
     * to the range list if OK. The block must be  be aligned properly,
     * and must not overlap any currently allocated block.
     */
    if (add_range(&(repl_state->ranges), p, size, repl_state->tracenum,
                  repl_state->num_ops) == 0)
        return;

    /* ADDED: cgw
     * fill range with low byte of index.  This will be used later
     * if we realloc the block and wish to make sure that the old
     * data was copied to the new block
     */
    memset(p, index & 0xFF, size);

    /* Remember region */
    repl_state->blocks[index].is_valid = 1;
    repl_state->blocks[index].ptr = p;
    repl_state->blocks[index].size = size;
    return;
}

void free_cmd(const char *msg) {
    int index;
    char *p;
    if ((sscanf(msg, "f %d", &index) != 1) &&
        (sscanf(msg, "free %d", &index) != 1)) {
        printf("%s\n", "usage: f <index>");
        return;
    }
    if ((index < 0) || (index >= repl_state->num_blocks)) {
        printf("ERROR: index must be between 0 and %d\n",
               repl_state->num_blocks);
        return;
    }
    if (!(repl_state->blocks[index].is_valid)) {
        printf("ERROR: index not in use\n");
        return;
    }
    repl_state->num_ops++;
    /* Remove region from list and call student's free function */
    p = repl_state->blocks[index].ptr;
    remove_range(&(repl_state->ranges), p);
    mm_free(p);
    repl_state->blocks[index].is_valid = 0;
    return;
}

void remalloc_cmd(const char *msg) {
    int index, size, j;
    char *newp;
    char *oldp;
    if ((sscanf(msg, "r %d %d", &index, &size) != 2) &&
        (sscanf(msg, "realloc %d %d", &index, &size) != 2)) {
        printf("%s\n", "usage: r <index> <size>");
        return;
    }
    if ((index < 0) || (index >= repl_state->num_blocks)) {
        printf("ERROR: index must be between 0 and %d\n",
               repl_state->num_blocks);
        return;
    }
    // if (!(repl_state->blocks[index].is_valid)) {
    //     printf("ERROR: index is not in use\n");
    //     return;
    // }
    /* Call the student's realloc */
    oldp = repl_state->blocks[index].ptr;
    if ((newp = mm_realloc(oldp, size)) == NULL) {
        malloc_error(repl_state->tracenum, repl_state->num_ops,
                     "mm_realloc failed.");
        return;
    }

    /* Remove the old region from the range list */
    remove_range(&(repl_state->ranges), oldp);

    /* Check new block for correctness and add it to range list */
    if (add_range(&(repl_state->ranges), newp, size, repl_state->tracenum,
                  repl_state->num_ops) == 0)
        return;

    /* ADDED: cgw
     * Make sure that the new block contains the data from the old
     * block and then fill in the new block with the low order byte
     * of the new index
     */
    int oldsize = repl_state->blocks[index].size;
    if (size < oldsize) oldsize = size;
    for (j = 0; j < oldsize; j++) {
        if (newp[j] != (index & 0xFF)) {
            malloc_error(repl_state->tracenum, repl_state->num_ops,
                         "mm_realloc did not preserve the "
                         "data from old block");
            return;
        }
    }
    memset(newp, index & 0xFF, size);

    /* Remember region */
    repl_state->blocks[index].ptr = newp;
    repl_state->blocks[index].size = size;
    return;
}

/*
 * each command has a string in the repl
 * and a handler for when the command is
 * executed
 */
struct {
    const char *command;
    void (*handler)(const char *);
} cmd_table[] = {{"help", help_cmd},
                 {"h", help_cmd},
                 {"m", malloc_cmd},
                 {"malloc", malloc_cmd},
                 {"r", remalloc_cmd},
                 {"realloc", remalloc_cmd},
                 {"f", free_cmd},
                 {"free", free_cmd},
                 {"p", print_cmd},
                 {"print", print_cmd},
                 {"check_heap", check_heap_cmd},
                 {"ch", check_heap_cmd},
                 {"quit", quit_cmd},
                 {"q", quit_cmd},
                 {"reset", reset_cmd},
                 {"r", reset_cmd}};

/* runs the malloc REPL */
static void driver() {
    char line[MAXLINE];
    char cmd[MAXLINE];
    char *fgets_ret;
    int ret;
    unsigned i;
    repl_state = make_repl_state(MAX_REPL_SIZE);
    mem_init();
    reset_cmd("");
    printf(
        "Welcome to the Malloc REPL. (Enter 'help' to see available "
        "commands.)\n");
    while (1) {
        printf("> ");
        (void)fflush(stdout);
        fgets_ret = fgets(line, sizeof(line), stdin);
        if (fgets_ret == NULL) {
            printf("\n");
            break;
        }

        ret = sscanf(line, "%s", cmd);
        if (ret != 1) {
            fprintf(stderr,
                    "syntax error (first argument must be a command)\n");
            continue;
        }

        for (i = 0; i < sizeof(cmd_table) / sizeof(cmd_table[0]); i++) {
            if (!strcmp(cmd, cmd_table[i].command)) {
                cmd_table[i].handler(line);
                break;
            }
        }

        if (i == sizeof(cmd_table) / sizeof(cmd_table[0])) {
            fprintf(stderr, "error: no valid command specified\n");
            continue;
        }
    }
    clear_ranges(&(repl_state->ranges));
    free(repl_state);
    return;
}
