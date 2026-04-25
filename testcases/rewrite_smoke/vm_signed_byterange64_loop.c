/* PC-state VM that tracks the running min and max of bytes interpreted
 * as SIGNED int8_t across the lower n = (x & 7) + 1 bytes, then
 * returns (smax - smin) as a u64.
 *
 *   n = (x & 7) + 1;
 *   s = x; mn = +127; mx = -128;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     if ((int64_t)sb > mx) mx = sb;
 *     if ((int64_t)sb < mn) mn = sb;
 *     s >>= 8; n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_signed_byterange64_loop_target.
 *
 * Distinct from vm_byterange64_loop (UNSIGNED min/max -> umax/umin
 * intrinsics).  Here every byte is sext (int8_t), so 0x80..0xFF fold
 * into negative i64 and the reductions should fold to llvm.smax.i64
 * and llvm.smin.i64.  Worst-case range is 255 (-128 .. +127).
 */
#include <stdio.h>
#include <stdint.h>

enum SrVmPc {
    SR_LOAD_N    = 0,
    SR_INIT_REGS = 1,
    SR_CHECK     = 2,
    SR_BODY      = 3,
    SR_SHIFT     = 4,
    SR_DEC       = 5,
    SR_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_signed_byterange64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  mn = 0;
    int64_t  mx = 0;
    int      pc = SR_LOAD_N;

    while (1) {
        if (pc == SR_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = SR_INIT_REGS;
        } else if (pc == SR_INIT_REGS) {
            s  = x;
            mn = 127;
            mx = -128;
            pc = SR_CHECK;
        } else if (pc == SR_CHECK) {
            pc = (n > 0ull) ? SR_BODY : SR_HALT;
        } else if (pc == SR_BODY) {
            int8_t  sb = (int8_t)(s & 0xFFull);
            int64_t v  = (int64_t)sb;
            mx = (v > mx) ? v : mx;
            mn = (v < mn) ? v : mn;
            pc = SR_SHIFT;
        } else if (pc == SR_SHIFT) {
            s = s >> 8;
            pc = SR_DEC;
        } else if (pc == SR_DEC) {
            n = n - 1ull;
            pc = SR_CHECK;
        } else if (pc == SR_HALT) {
            return (uint64_t)(mx - mn);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_sgn_byterange64(0x807F807F807F807F)=%llu\n",
           (unsigned long long)vm_signed_byterange64_loop_target(0x807F807F807F807Full));
    return 0;
}
