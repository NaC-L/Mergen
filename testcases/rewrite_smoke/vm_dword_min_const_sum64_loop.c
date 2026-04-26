/* PC-state VM: r += umin(dword, 0x40000000) per iter:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     uint64_t m = (d < 0x40000000) ? d : 0x40000000;
 *     r = r + m;
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_min_const_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_word_min_const_sum64_loop  (16-bit stride)
 *   - vm_dword_max_const_sum64_loop (umax counterpart at same stride)
 *
 * Tests `llvm.umin.i64` against constant inside add chain at u32
 * stride.
 */
#include <stdio.h>
#include <stdint.h>

enum DnmVmPc {
    DNM_INIT_ALL = 0,
    DNM_CHECK    = 1,
    DNM_BODY     = 2,
    DNM_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_min_const_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = DNM_INIT_ALL;

    while (1) {
        if (pc == DNM_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DNM_CHECK;
        } else if (pc == DNM_CHECK) {
            pc = (n > 0ull) ? DNM_BODY : DNM_HALT;
        } else if (pc == DNM_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            uint64_t m = (d < 0x40000000ull) ? d : 0x40000000ull;
            r = r + m;
            s = s >> 32;
            n = n - 1ull;
            pc = DNM_CHECK;
        } else if (pc == DNM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_min_const_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dword_min_const_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
