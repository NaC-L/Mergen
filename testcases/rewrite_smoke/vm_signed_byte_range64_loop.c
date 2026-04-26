/* PC-state VM tracking running min and max of SIGNED i8 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; mn = +127; mx = -128;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     int64_t v = (int64_t)sb;
 *     if (v > mx) mx = v;
 *     if (v < mn) mn = v;
 *     s >>= 8;
 *     n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_byte_range64_loop_target.
 *
 * Distinct from:
 *   - vm_signed_word_range64_loop  (16-bit signed lane stride)
 *   - vm_signed_dword_range64_loop (32-bit signed lane stride)
 *   - vm_byterange64_loop          (UNSIGNED u8 cmp -> umax/umin folds)
 *
 * Tests sext-i8 + SIGNED cmp+select reductions at byte stride.  Per
 * documented lifter asymmetry, signed cmp+select stays as raw
 * `icmp slt + select` (does NOT fold to llvm.smax.i64/smin.i64).  Uses
 * n-decrement loop control (4 stateful slots: n, s, mn, mx).
 */
#include <stdio.h>
#include <stdint.h>

enum SbrVmPc {
    SBR_INIT_ALL = 0,
    SBR_CHECK    = 1,
    SBR_BODY     = 2,
    SBR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_signed_byte_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SBR_INIT_ALL;

    while (1) {
        if (pc == SBR_INIT_ALL) {
            n  = (x & 7ull) + 1ull;
            s  = x;
            mn = 127;
            mx = -128;
            pc = SBR_CHECK;
        } else if (pc == SBR_CHECK) {
            pc = (n > 0ull) ? SBR_BODY : SBR_HALT;
        } else if (pc == SBR_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            int64_t v  = (int64_t)sb;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            s = s >> 8;
            n = n - 1ull;
            pc = SBR_CHECK;
        } else if (pc == SBR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_byte_range64(0x807F)=%llu\n",
           (unsigned long long)vm_signed_byte_range64_loop_target(0x807Full));
    return 0;
}
