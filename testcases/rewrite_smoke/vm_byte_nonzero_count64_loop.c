/* PC-state VM that counts nonzero bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b != 0) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_nonzero_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (eq vs FIXED reference)
 *   - vm_byte_lt_thresh_count64_loop (ult vs CONSTANT)
 *
 * Tests `icmp ne 0` predicate at byte stride.  Adds the `ne`
 * predicate to the cmp-counter coverage matrix.
 */
#include <stdio.h>
#include <stdint.h>

enum BnVmPc {
    BN_INIT_ALL = 0,
    BN_CHECK    = 1,
    BN_BODY     = 2,
    BN_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_nonzero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BN_INIT_ALL;

    while (1) {
        if (pc == BN_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BN_CHECK;
        } else if (pc == BN_CHECK) {
            pc = (n > 0ull) ? BN_BODY : BN_HALT;
        } else if (pc == BN_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b != 0ull) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BN_CHECK;
        } else if (pc == BN_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_nonzero_count64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_nonzero_count64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
