#include <stdint.h>

__attribute__((section("hello"), used))
int hello_func(void *args)
{
    return 1;
}
