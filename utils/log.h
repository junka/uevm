#ifndef _VC_LOG_H_
#define _VC_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif


enum log_level {
    LOG_FATAL,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_VERBOSE,
};

void logging_print(int level, const char *format, ...)
        __attribute__((format(printf, 2, 3)));

#define __pr(level, fmt, ...)   \
do {                            \
    logging_print(level, "vccm: " fmt, ##__VA_ARGS__);    \
} while (0)

#define log_error(fmt, ...) __pr(LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) __pr(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) __pr(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_debug(fmt, ...) __pr(LOG_DEBUG, fmt, ##__VA_ARGS__)

#define LOG()

#ifdef __cplusplus
}
#endif

#endif /*_VC_LOG_H_*/