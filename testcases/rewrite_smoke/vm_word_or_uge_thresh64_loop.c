/* PC-state VM that OR-accumulates u16 words >= 0x8000:
 *
 *   n = (x & 3) + 1;
 *   s = x; acc = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     acc = acc | ((w >= 0x8000) ? w : 0);
 *     s >>= 16;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_word_or_uge_thresh64_loop_target.
 *
 * Predicate-gated OR accumulator at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WorVmPc {
    WOR_INIT_ALL = 0,
    WOR_CHECK    = 1,
    WOR_BODY     = 2,
    WOR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_or_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = WOR_INIT_ALL;

    while (1) {
        if (pc == WOR_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            acc = 0ull;
            pc = WOR_CHECK;
        } else if (pc == WOR_CHECK) {
            pc = (n > 0ull) ? WOR_BODY : WOR_HALT;
        } else if (pc == WOR_BODY) {
            uint64_t w = s & 0xFFFFull;
            acc = acc | ((w >= 0x8000ull) ? w : 0ull);
            s = s >> 16;
            n = n - 1ull;
            pc = WOR_CHECK;
        } else if (pc == WOR_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_or_uge_thresh64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_or_uge_thresh64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
