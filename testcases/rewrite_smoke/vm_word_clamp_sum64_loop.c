/* PC-state VM: clamp u16 word to [0x4000, 0x8000] then sum:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t w  = s & 0xFFFF;
 *     uint64_t lo = (w > 0x4000) ? w : 0x4000;     // umax(w, 0x4000)
 *     uint64_t cl = (lo < 0x8000) ? lo : 0x8000;   // umin(lo, 0x8000)
 *     r = r + cl;
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_clamp_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_clamp_sum64_loop  (8-bit stride)
 *   - vm_word_max_const_sum64_loop (umax only)
 *   - vm_word_min_const_sum64_loop (umin only)
 *
 * Tests `llvm.umax.i64` chained with `llvm.umin.i64` (clamp idiom)
 * inside add chain at u16 word stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WclVmPc {
    WCL_INIT_ALL = 0,
    WCL_CHECK    = 1,
    WCL_BODY     = 2,
    WCL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_clamp_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = WCL_INIT_ALL;

    while (1) {
        if (pc == WCL_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WCL_CHECK;
        } else if (pc == WCL_CHECK) {
            pc = (n > 0ull) ? WCL_BODY : WCL_HALT;
        } else if (pc == WCL_BODY) {
            uint64_t w  = s & 0xFFFFull;
            uint64_t lo = (w > 0x4000ull) ? w : 0x4000ull;
            uint64_t cl = (lo < 0x8000ull) ? lo : 0x8000ull;
            r = r + cl;
            s = s >> 16;
            n = n - 1ull;
            pc = WCL_CHECK;
        } else if (pc == WCL_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_clamp_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_clamp_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
