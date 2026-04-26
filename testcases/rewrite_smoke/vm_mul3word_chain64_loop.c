/* PC-state VM that runs Horner-style hash with multiplier 3 over u16
 * words:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r * 3 + (s & 0xFFFF);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_mul3word_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_mul3byte_chain64_loop  (8-bit lane stride, same multiplier 3)
 *   - vm_word_horner13_64_loop  (multiplier *13)
 *   - vm_djb2_word64_loop       (multiplier *33)
 *
 * Tests `mul i64 r, 3` (small-constant multiplier) at u16 word stride.
 */
#include <stdio.h>
#include <stdint.h>

enum M3wVmPc {
    M3W_INIT_ALL = 0,
    M3W_CHECK    = 1,
    M3W_BODY     = 2,
    M3W_INC      = 3,
    M3W_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_mul3word_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = M3W_INIT_ALL;

    while (1) {
        if (pc == M3W_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = M3W_CHECK;
        } else if (pc == M3W_CHECK) {
            pc = (i < n) ? M3W_BODY : M3W_HALT;
        } else if (pc == M3W_BODY) {
            r = r * 3ull + (s & 0xFFFFull);
            s = s >> 16;
            pc = M3W_INC;
        } else if (pc == M3W_INC) {
            i = i + 1ull;
            pc = M3W_CHECK;
        } else if (pc == M3W_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_mul3word_chain64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_mul3word_chain64_loop_target(0xCAFEBABEull));
    return 0;
}
