/* PC-state VM that counts signed bytes >= 0 (non-negative):
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     cnt = cnt + ((sb >= 0) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_sge_zero_count64_loop_target.
 *
 * Tests `icmp sge 0` (signed greater-or-equal) at byte stride.
 * Adds the `sge` predicate to the cmp-counter coverage matrix.
 */
#include <stdio.h>
#include <stdint.h>

enum BsgeVmPc {
    BSGE_INIT_ALL = 0,
    BSGE_CHECK    = 1,
    BSGE_BODY     = 2,
    BSGE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_sge_zero_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BSGE_INIT_ALL;

    while (1) {
        if (pc == BSGE_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BSGE_CHECK;
        } else if (pc == BSGE_CHECK) {
            pc = (n > 0ull) ? BSGE_BODY : BSGE_HALT;
        } else if (pc == BSGE_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            cnt = cnt + ((sb >= (int8_t)0) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BSGE_CHECK;
        } else if (pc == BSGE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_sge_zero_count64(0x7F7F7F7F7F7F7F7F)=%llu\n",
           (unsigned long long)vm_byte_sge_zero_count64_loop_target(0x7F7F7F7F7F7F7F7Full));
    return 0;
}
