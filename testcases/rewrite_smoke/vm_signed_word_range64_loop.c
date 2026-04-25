/* PC-state VM tracking running min and max of SIGNED i16 words:
 *
 *   n = (x & 3) + 1;
 *   s = x; mn = +32767; mx = -32768;
 *   while (n) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     int64_t v = (int64_t)sw;
 *     if (v > mx) mx = v;
 *     if (v < mn) mn = v;
 *     s >>= 16;
 *     n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_word_range64_loop_target.
 *
 * Distinct from:
 *   - vm_word_range64_loop          (UNSIGNED u16 cmp -> umax/umin folds)
 *   - vm_signed_byterange64_loop    (signed i8, 8-bit stride)
 *
 * Tests sext-i16 + SIGNED cmp+select reductions at word stride.
 * Per documented lifter asymmetry, signed cmp+select stays as raw
 * `icmp slt + select` (does NOT fold to llvm.smax.i64/smin.i64).
 * Uses n-decrement loop control (4 stateful slots: n,s,mn,mx).
 */
#include <stdio.h>
#include <stdint.h>

enum SwrVmPc {
    SWR_INIT_ALL = 0,
    SWR_CHECK    = 1,
    SWR_BODY     = 2,
    SWR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_signed_word_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SWR_INIT_ALL;

    while (1) {
        if (pc == SWR_INIT_ALL) {
            n  = (x & 3ull) + 1ull;
            s  = x;
            mn = 32767;
            mx = -32768;
            pc = SWR_CHECK;
        } else if (pc == SWR_CHECK) {
            pc = (n > 0ull) ? SWR_BODY : SWR_HALT;
        } else if (pc == SWR_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            int64_t v  = (int64_t)sw;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            s = s >> 16;
            n = n - 1ull;
            pc = SWR_CHECK;
        } else if (pc == SWR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_word_range64(0x80007FFF)=%llu\n",
           (unsigned long long)vm_signed_word_range64_loop_target(0x80007FFFull));
    return 0;
}
