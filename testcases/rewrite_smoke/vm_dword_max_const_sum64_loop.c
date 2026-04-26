/* PC-state VM: r += umax(dword, 0x40000000) per iter:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     uint64_t m = (d > 0x40000000) ? d : 0x40000000;
 *     r = r + m;
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_max_const_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_word_max_const_sum64_loop (16-bit stride)
 *   - vm_byte_max_const_sum64_loop (8-bit stride)
 *
 * Tests `llvm.umax.i64` fold (cmp-and-select against constant) inside
 * add chain at u32 stride.  Trip count is at most 2 (n_mask=1) so the
 * full `+max(d0)+max(d1)` path is exercised when low bit is set.
 */
#include <stdio.h>
#include <stdint.h>

enum DmcVmPc {
    DMC_INIT_ALL = 0,
    DMC_CHECK    = 1,
    DMC_BODY     = 2,
    DMC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_max_const_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = DMC_INIT_ALL;

    while (1) {
        if (pc == DMC_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DMC_CHECK;
        } else if (pc == DMC_CHECK) {
            pc = (n > 0ull) ? DMC_BODY : DMC_HALT;
        } else if (pc == DMC_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            uint64_t m = (d > 0x40000000ull) ? d : 0x40000000ull;
            r = r + m;
            s = s >> 32;
            n = n - 1ull;
            pc = DMC_CHECK;
        } else if (pc == DMC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_max_const_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dword_max_const_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
