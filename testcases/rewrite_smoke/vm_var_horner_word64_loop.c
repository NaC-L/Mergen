/* PC-state VM: variable Horner over u16 words with multiplier from
 * loop counter:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r * (n + 1) + (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_var_horner_word64_loop_target.
 *
 * Distinct from:
 *   - vm_var_horner64_loop      (byte stride, same shape)
 *   - vm_word_horner13_64_loop  (constant multiplier 13)
 *   - vm_mul3word_chain64_loop  (constant multiplier 3)
 *
 * Tests Horner-style chain at u16 stride where the multiplier is the
 * LOOP COUNTER (n+1).  Multiplier varies from (init_n+1) down to 2
 * across iterations.
 */
#include <stdio.h>
#include <stdint.h>

enum VhwVmPc {
    VHW_INIT_ALL = 0,
    VHW_CHECK    = 1,
    VHW_BODY     = 2,
    VHW_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_var_horner_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = VHW_INIT_ALL;

    while (1) {
        if (pc == VHW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = VHW_CHECK;
        } else if (pc == VHW_CHECK) {
            pc = (n > 0ull) ? VHW_BODY : VHW_HALT;
        } else if (pc == VHW_BODY) {
            r = r * (n + 1ull) + (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = VHW_CHECK;
        } else if (pc == VHW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_var_horner_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_var_horner_word64_loop_target(0xCAFEBABEull));
    return 0;
}
