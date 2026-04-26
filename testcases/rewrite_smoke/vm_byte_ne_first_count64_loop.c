/* PC-state VM that counts bytes not equal to the first byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; first = s & 0xFF; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b != first) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_ne_first_count64_loop_target.
 *
 * Tests `icmp ne` cmp-counter with captured-reference comparand at byte
 * stride.  Distinct from vm_byte_eq_first_count64_loop (eq vs same
 * captured ref) and vm_byte_nonzero_count64_loop (ne vs constant 0).
 * 4 stateful slots (n, s, first, cnt) within budget.
 */
#include <stdio.h>
#include <stdint.h>

enum BneVmPc {
    BNE_INIT_ALL = 0,
    BNE_CHECK    = 1,
    BNE_BODY     = 2,
    BNE_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_ne_first_count64_loop_target(uint64_t x) {
    uint64_t n     = 0;
    uint64_t s     = 0;
    uint64_t first = 0;
    uint64_t cnt   = 0;
    int      pc    = BNE_INIT_ALL;

    while (1) {
        if (pc == BNE_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            first = x & 0xFFull;
            cnt = 0ull;
            pc = BNE_CHECK;
        } else if (pc == BNE_CHECK) {
            pc = (n > 0ull) ? BNE_BODY : BNE_HALT;
        } else if (pc == BNE_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b != first) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BNE_CHECK;
        } else if (pc == BNE_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_ne_first_count64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_byte_ne_first_count64_loop_target(0xDEADBEEFull));
    return 0;
}
