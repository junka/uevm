#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "log.h"

static void
usage(void (*usage_cb)(), char *prog, char *version)
{
    printf("%s: %s\n\n", prog, version);
    if (usage_cb)
        usage_cb();
    printf("\t--run, -r obj\tspecify the object\n");
    printf("\t--load, -l\n");
    printf("\t--version, -V\tshow program version\n");
    printf("\t--verbose, -v\tshow debug verbose messages\n");
    printf("\t--help, -h\tshow this help\n");
}

int
parse_options(int argc, char * const *argv, void (*usage_cb)(), char *prog, char *version, char *path)
{
    static const struct option long_options[] = {
        {"run", required_argument, NULL, 'r'},
        {"load", no_argument, NULL, 'l'},
        {"version", no_argument, NULL, 'V'},
        {"verbose", optional_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    const char *short_options = "r:lVv::h";
    const int n_long_options = sizeof(long_options)/sizeof(long_options[0]);
    memset(path, 0, 1024);

    for (;;) {
        int idx;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &idx);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(usage_cb, prog, version);
            exit(0);

        case 'V':
            printf("%s: version %s\n", prog, version);
            exit(0);
        case 'v':
            log_set_level(LOG_VERBOSE);
            break;

        case 'r':
            strcpy(path, optarg);
            break;

        case '?':
            exit(1);

        case 0:
            break;

        default:
            abort();
        }
    }
    return 0;
}