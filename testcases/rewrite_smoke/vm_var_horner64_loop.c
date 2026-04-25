/* PC-state VM: variable Horner with multiplier from loop counter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r * (n + 1) + (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_var_horner64_loop_target.
 *
 * Distinct from:
 *   - vm_mul3byte_chain64_loop  (mul *3 constant)
 *   - vm_djb264_loop           (mul *33 constant)
 *   - vm_dword_horner7_64_loop (mul *7 constant)
 *
 * Tests Horner-style chain where the multiplier is the LOOP COUNTER
 * (n+1) - changes each iteration.  Multiplier varies from (init_n+1)
 * down to 2 across the iterations.  All-FF n=8 produces a complex
 * factorial-weighted byte sum.
 */
#include <stdio.h>
#include <stdint.h>

enum VhVmPc {
    VH_INIT_ALL = 0,
    VH_CHECK    = 1,
    VH_BODY     = 2,
    VH_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_var_horner64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = VH_INIT_ALL;

    while (1) {
        if (pc == VH_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = VH_CHECK;
        } else if (pc == VH_CHECK) {
            pc = (n > 0ull) ? VH_BODY : VH_HALT;
        } else if (pc == VH_BODY) {
            r = r * (n + 1ull) + (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = VH_CHECK;
        } else if (pc == VH_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_var_horner64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_var_horner64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
