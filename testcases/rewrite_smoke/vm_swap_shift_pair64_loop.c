/* PC-state VM: two-state cross-feed with shift mixing:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x;
 *   while (n) {
 *     uint64_t t = a;
 *     a = b ^ (a >> 1);
 *     b = t + (b << 1);
 *     n--;
 *   }
 *   return a + b;
 *
 * Lift target: vm_swap_shift_pair64_loop_target.
 *
 * Distinct from:
 *   - vm_pairmix64_loop          (a+b temp + mul-by-GR cross-feed)
 *   - vm_orxor_pair64_loop       (a|b + xor-mul cross-feed)
 *   - vm_threestate_xormul64_loop (three-state cross-feed)
 *
 * Tests two-state recurrence where one slot uses XOR + lshr-1 of
 * old self and the other uses ADD + shl-1 of old self.  Explicit
 * temp barrier (`t = a`) preserves a's original value for b's
 * update.  Returns combined a+b.
 */
#include <stdio.h>
#include <stdint.h>

enum SsVmPc {
    SS_INIT_ALL = 0,
    SS_CHECK    = 1,
    SS_BODY     = 2,
    SS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_swap_shift_pair64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    int      pc = SS_INIT_ALL;

    while (1) {
        if (pc == SS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            pc = SS_CHECK;
        } else if (pc == SS_CHECK) {
            pc = (n > 0ull) ? SS_BODY : SS_HALT;
        } else if (pc == SS_BODY) {
            uint64_t t = a;
            a = b ^ (a >> 1);
            b = t + (b << 1);
            n = n - 1ull;
            pc = SS_CHECK;
        } else if (pc == SS_HALT) {
            return a + b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_swap_shift_pair64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_swap_shift_pair64_loop_target(0xCAFEBABEull));
    return 0;
}
