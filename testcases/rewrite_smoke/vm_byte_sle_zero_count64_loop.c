/* PC-state VM that counts signed bytes <= 0:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     cnt = cnt + ((sb <= 0) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_sle_zero_count64_loop_target.
 *
 * Tests `icmp sle 0` (signed less-or-equal) at byte stride.  Adds the
 * `sle` predicate.  With this sample, all 10 LLVM integer predicates
 * (eq/ne/ult/ule/ugt/uge/slt/sle/sgt/sge) are covered at byte stride.
 */
#include <stdio.h>
#include <stdint.h>

enum BsleVmPc {
    BSLE_INIT_ALL = 0,
    BSLE_CHECK    = 1,
    BSLE_BODY     = 2,
    BSLE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_sle_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BSLE_INIT_ALL;

    while (1) {
        if (pc == BSLE_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BSLE_CHECK;
        } else if (pc == BSLE_CHECK) {
            pc = (n > 0ull) ? BSLE_BODY : BSLE_HALT;
        } else if (pc == BSLE_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            cnt = cnt + ((sb <= (int8_t)0) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BSLE_CHECK;
        } else if (pc == BSLE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_sle_zero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_sle_zero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
