/* PC-state VM that counts SIGNED bytes < 0 (i.e. high bit set):
 *
 *   n = (x & 7) + 1;
 *   s = x; cnt = 0;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     cnt = cnt + ((sb < 0) ? 1 : 0);
 *     s >>= 8;
 *     n--;
 *   }
 *   return cnt;
 *
 * Lift target: vm_byte_signed_lt_count64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_lt_thresh_count64_loop (UNSIGNED ult)
 *   - vm_byte_gt_thresh_count64_loop (UNSIGNED ugt)
 *
 * Tests `icmp slt` (signed less-than against 0) + zext + add chain.
 * Equivalent to "count bytes with high bit set" but expressed via
 * signed compare; lifter sees sext-i8 + signed predicate.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_signed_lt_count64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t cnt = 0;
    int      pc  = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            cnt = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (n > 0ull) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            cnt = cnt + ((sb < 0) ? 1ull : 0ull);
            s = s >> 8;
            n = n - 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return cnt;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_signed_lt_count64(0x80808080FFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_signed_lt_count64_loop_target(0x80808080FFFFFFFFull));
    return 0;
}
