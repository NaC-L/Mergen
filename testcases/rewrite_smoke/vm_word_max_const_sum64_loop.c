/* PC-state VM: r += umax(word, 0x4000) per iter:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     uint64_t m = (w > 0x4000) ? w : 0x4000;     // umax against constant
 *     r = r + m;
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_max_const_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_max_const_sum64_loop (8-bit stride)
 *   - vm_word_addchain64_loop      (no max)
 *
 * Tests `llvm.umax.i64` fold (cmp-and-select against constant) inside
 * add chain at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WmcVmPc {
    WMC_INIT_ALL = 0,
    WMC_CHECK    = 1,
    WMC_BODY     = 2,
    WMC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_max_const_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = WMC_INIT_ALL;

    while (1) {
        if (pc == WMC_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WMC_CHECK;
        } else if (pc == WMC_CHECK) {
            pc = (n > 0ull) ? WMC_BODY : WMC_HALT;
        } else if (pc == WMC_BODY) {
            uint64_t w = s & 0xFFFFull;
            uint64_t m = (w > 0x4000ull) ? w : 0x4000ull;
            r = r + m;
            s = s >> 16;
            n = n - 1ull;
            pc = WMC_CHECK;
        } else if (pc == WMC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_max_const_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_max_const_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
