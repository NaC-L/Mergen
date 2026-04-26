/* PC-state VM: r += umin(word, 0x4000) per iter:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     uint64_t m = (w < 0x4000) ? w : 0x4000;     // umin against constant
 *     r = r + m;
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_min_const_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_min_const_sum64_loop (8-bit stride)
 *   - vm_word_max_const_sum64_loop (umax counterpart at same stride)
 *
 * Tests `llvm.umin.i64` against constant inside add chain at u16
 * stride.  Lifter folds the `(w < C) ? w : C` idiom to umin.
 */
#include <stdio.h>
#include <stdint.h>

enum WnmVmPc {
    WNM_INIT_ALL = 0,
    WNM_CHECK    = 1,
    WNM_BODY     = 2,
    WNM_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_min_const_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = WNM_INIT_ALL;

    while (1) {
        if (pc == WNM_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WNM_CHECK;
        } else if (pc == WNM_CHECK) {
            pc = (n > 0ull) ? WNM_BODY : WNM_HALT;
        } else if (pc == WNM_BODY) {
            uint64_t w = s & 0xFFFFull;
            uint64_t m = (w < 0x4000ull) ? w : 0x4000ull;
            r = r + m;
            s = s >> 16;
            n = n - 1ull;
            pc = WNM_CHECK;
        } else if (pc == WNM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_min_const_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_min_const_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
