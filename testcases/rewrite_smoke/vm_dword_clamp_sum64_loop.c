/* PC-state VM: clamp u32 dword to [0x40000000, 0x80000000] then sum:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t d  = s & 0xFFFFFFFF;
 *     uint64_t lo = (d > 0x40000000) ? d : 0x40000000;
 *     uint64_t cl = (lo < 0x80000000) ? lo : 0x80000000;
 *     r = r + cl;
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_clamp_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_word_clamp_sum64_loop      (16-bit stride)
 *   - vm_dword_max_const_sum64_loop (umax only)
 *   - vm_dword_min_const_sum64_loop (umin only)
 *
 * Tests `llvm.umax.i64` chained with `llvm.umin.i64` (clamp idiom)
 * inside add chain at u32 dword stride.
 */
#include <stdio.h>
#include <stdint.h>

enum DclVmPc {
    DCL_INIT_ALL = 0,
    DCL_CHECK    = 1,
    DCL_BODY     = 2,
    DCL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_clamp_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = DCL_INIT_ALL;

    while (1) {
        if (pc == DCL_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DCL_CHECK;
        } else if (pc == DCL_CHECK) {
            pc = (n > 0ull) ? DCL_BODY : DCL_HALT;
        } else if (pc == DCL_BODY) {
            uint64_t d  = s & 0xFFFFFFFFull;
            uint64_t lo = (d > 0x40000000ull) ? d : 0x40000000ull;
            uint64_t cl = (lo < 0x80000000ull) ? lo : 0x80000000ull;
            r = r + cl;
            s = s >> 32;
            n = n - 1ull;
            pc = DCL_CHECK;
        } else if (pc == DCL_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_clamp_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_clamp_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
