/* PC-state VM that computes an alternating-sign u32 dword sum:
 *   r = +d0 - d1 over n = (x & 1) + 1 dwords
 * with r kept as a signed i64 accumulator and returned as u64.
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0; sign = 1;
 *   while (n) {
 *     r += sign * (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     sign = -sign;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_altdwordsum64_loop_target.
 *
 * Distinct from:
 *   - vm_altwordsum64_loop  (16-bit word stride)
 *   - vm_altbytesum64_loop  (8-bit byte stride)
 *   - vm_signed_dword_sum64_loop (sext-i32 add without sign flip)
 *
 * Tests: signed accumulator, sign flip per iteration via negation,
 * signed-times-zext-u32 multiply at 32-bit dword stride.
 * Trip count is at most 2 (n_mask=1) so x with low-bit-set covers
 * the full +d0-d1 path.
 */
#include <stdio.h>
#include <stdint.h>

enum AdVmPc {
    AD_LOAD_N    = 0,
    AD_INIT_REGS = 1,
    AD_CHECK     = 2,
    AD_ACC       = 3,
    AD_SHIFT     = 4,
    AD_FLIP      = 5,
    AD_DEC       = 6,
    AD_HALT      = 7,
};

__declspec(noinline)
uint64_t vm_altdwordsum64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    int64_t  r    = 0;
    int64_t  sign = 1;
    int      pc   = AD_LOAD_N;

    while (1) {
        if (pc == AD_LOAD_N) {
            n = (x & 1ull) + 1ull;
            pc = AD_INIT_REGS;
        } else if (pc == AD_INIT_REGS) {
            s    = x;
            r    = 0;
            sign = 1;
            pc = AD_CHECK;
        } else if (pc == AD_CHECK) {
            pc = (n > 0ull) ? AD_ACC : AD_HALT;
        } else if (pc == AD_ACC) {
            r = r + sign * (int64_t)(s & 0xFFFFFFFFull);
            pc = AD_SHIFT;
        } else if (pc == AD_SHIFT) {
            s = s >> 32;
            pc = AD_FLIP;
        } else if (pc == AD_FLIP) {
            sign = -sign;
            pc = AD_DEC;
        } else if (pc == AD_DEC) {
            n = n - 1ull;
            pc = AD_CHECK;
        } else if (pc == AD_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_altdwordsum64(0x0000000100000003)=%llu\n",
           (unsigned long long)vm_altdwordsum64_loop_target(0x0000000100000003ull));
    return 0;
}
