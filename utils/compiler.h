#ifndef _VC_COMPILER_H_
#define _VC_COMPILER_H_

#ifdef __cplusplus
extern "C" {
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)



#define ___vm_mvb(x, b, n, m) ((uint##b##_t)(x) << (b-(n+1)*8) >> (b-8) << (m*8))

#define ___vm_swab16(x) ((uint16_t)(			\
                ___vm_mvb(x, 16, 0, 1) |	\
                ___vm_mvb(x, 16, 1, 0)))

#define ___vm_swab32(x) ((uint32_t)(			\
                ___vm_mvb(x, 32, 0, 3) |	\
                ___vm_mvb(x, 32, 1, 2) |	\
                ___vm_mvb(x, 32, 2, 1) |	\
                ___vm_mvb(x, 32, 3, 0)))

#define ___vm_swab64(x) ((uint64_t)(			\
                ___vm_mvb(x, 64, 0, 7) |	\
                ___vm_mvb(x, 64, 1, 6) |	\
                ___vm_mvb(x, 64, 2, 5) |	\
                ___vm_mvb(x, 64, 3, 4) |	\
                ___vm_mvb(x, 64, 4, 3) |	\
                ___vm_mvb(x, 64, 5, 2) |	\
                ___vm_mvb(x, 64, 6, 1) |	\
                ___vm_mvb(x, 64, 7, 0)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __vm_ntohs(x)         __builtin_bswap16(x)
# define __vm_htons(x)         __builtin_bswap16(x)
# define __vm_constant_ntohs(x)    ___vm_swab16(x)
# define __vm_constant_htons(x)    ___vm_swab16(x)
# define __vm_ntohl(x)         __builtin_bswap32(x)
# define __vm_htonl(x)         __builtin_bswap32(x)
# define __vm_constant_ntohl(x)    ___vm_swab32(x)
# define __vm_constant_htonl(x)    ___vm_swab32(x)
# define __vm_be64_to_cpu(x)       __builtin_bswap64(x)
# define __vm_cpu_to_be64(x)       __builtin_bswap64(x)
# define __vm_constant_be64_to_cpu(x)  ___vm_swab64(x)
# define __vm_constant_cpu_to_be64(x)  ___vm_swab64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __vm_ntohs(x)         (x)
# define __vm_htons(x)         (x)
# define __vm_constant_ntohs(x)    (x)
# define __vm_constant_htons(x)    (x)
# define __vm_ntohl(x)         (x)
# define __vm_htonl(x)         (x)
# define __vm_constant_ntohl(x)    (x)
# define __vm_constant_htonl(x)    (x)
# define __vm_be64_to_cpu(x)       (x)
# define __vm_cpu_to_be64(x)       (x)
# define __vm_constant_be64_to_cpu(x)  (x)
# define __vm_constant_cpu_to_be64(x)  (x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define vm_htons(x)                \
    (__builtin_constant_p(x) ?      \
     __vm_constant_htons(x) : __vm_htons(x))
#define vm_ntohs(x)                \
    (__builtin_constant_p(x) ?      \
     __vm_constant_ntohs(x) : __vm_ntohs(x))
#define vm_htonl(x)                \
    (__builtin_constant_p(x) ?      \
     __vm_constant_htonl(x) : __vm_htonl(x))
#define vm_ntohl(x)                \
    (__builtin_constant_p(x) ?      \
     __vm_constant_ntohl(x) : __vm_ntohl(x))
#define vm_cpu_to_be64(x)          \
    (__builtin_constant_p(x) ?      \
     __vm_constant_cpu_to_be64(x) : __vm_cpu_to_be64(x))
#define vm_be64_to_cpu(x)          \
    (__builtin_constant_p(x) ?      \
     __vm_constant_be64_to_cpu(x) : __vm_be64_to_cpu(x))

#ifdef __cplusplus
}
#endif

#endif /*_VC_COMPILER_H_*/