#include <stdarg.h>
#include <stdio.h>

#include <log.h>




static int log_level = LOG_INFO;

static int
print_func(int level, const char *format, va_list args)
{
    if (level > log_level)
        return 0;

    return vfprintf(stderr, format, args);
}

void __attribute__((format(printf, 2, 3)))
logging_print(int level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    print_func(level, format, args);
    print_func(level, "\n", args);
    va_end(args);
}

void
log_set_level(int v)
{
    log_level = v;
}