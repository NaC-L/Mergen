/* PC-state VM: count of bytes strictly > previous byte:
 *
 *   n = (x & 7) + 1;
 *   s = x; prev = s & 0xFF; cnt = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     cnt = cnt + ((b > prev) ? 1 : 0);
 *     prev = b;
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_increase_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_eq_first_count64_loop (compares against fixed first)
 *   - vm_byte_lt_thresh_count64_loop (compares against constant)
 *
 * Tests CROSS-ITER byte comparison: each iter compares current byte
 * to the byte from previous iter (stored in `prev` slot).  4 stateful
 * slots (n, s, prev, cnt).  First iter always counts 0 (b == prev).
 */
#include <stdio.h>
#include <stdint.h>

enum BiVmPc {
    BI_INIT_ALL = 0,
    BI_CHECK    = 1,
    BI_BODY     = 2,
    BI_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_increase_count64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    uint64_t prev = 0;
    uint64_t cnt  = 0;
    int      pc   = BI_INIT_ALL;

    while (1) {
        if (pc == BI_INIT_ALL) {
            n    = (x & 7ull) + 1ull;
            s    = x;
            prev = x & 0xFFull;
            cnt  = 0ull;
            pc = BI_CHECK;
        } else if (pc == BI_CHECK) {
            pc = (n > 0ull) ? BI_BODY : BI_HALT;
        } else if (pc == BI_BODY) {
            uint64_t b = s & 0xFFull;
            cnt = cnt + ((b > prev) ? 1ull : 0ull);
            prev = b;
            s = s >> 8;
            n = n - 1ull;
            pc = BI_CHECK;
        } else if (pc == BI_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_increase_count64(0x807060504030201F)=%llu\n",
           (unsigned long long)vm_byte_increase_count64_loop_target(0x807060504030201Full));
    return 0;
}
