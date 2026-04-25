/* PC-state VM tracking signed-i32 dword min/max range:
 *
 *   n = (x & 1) + 1;
 *   s = x; mn = INT32_MAX; mx = INT32_MIN;
 *   while (n) {
 *     int32_t sd = (int32_t)(s & 0xFFFFFFFF);
 *     int64_t v  = (int64_t)sd;
 *     if (v > mx) mx = v;
 *     if (v < mn) mn = v;
 *     s >>= 32;
 *     n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_dword_range64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_range64_loop          (UNSIGNED u32 -> umax/umin folds)
 *   - vm_signed_byterange64_loop     (signed i8, 8-bit stride)
 *   - vm_signed_word_range64_loop    (signed i16, 16-bit stride)
 *
 * Completes the range coverage matrix (3 widths x 2 signs).  Per
 * documented signed-cmp asymmetry, signed cmp+select stays raw
 * `icmp slt + select` rather than folding to llvm.smax.i64/smin.i64.
 * 4 stateful slots (n,s,mn,mx) with n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum SdrVmPc {
    SDR_INIT_ALL = 0,
    SDR_CHECK    = 1,
    SDR_BODY     = 2,
    SDR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_signed_dword_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SDR_INIT_ALL;

    while (1) {
        if (pc == SDR_INIT_ALL) {
            n  = (x & 1ull) + 1ull;
            s  = x;
            mn = 2147483647;
            mx = -2147483648LL;
            pc = SDR_CHECK;
        } else if (pc == SDR_CHECK) {
            pc = (n > 0ull) ? SDR_BODY : SDR_HALT;
        } else if (pc == SDR_BODY) {
            int32_t sd = (int32_t)(s & 0xFFFFFFFFull);
            int64_t v  = (int64_t)sd;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            s = s >> 32;
            n = n - 1ull;
            pc = SDR_CHECK;
        } else if (pc == SDR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_dword_range64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_signed_dword_range64_loop_target(0xDEADBEEFull));
    return 0;
}
