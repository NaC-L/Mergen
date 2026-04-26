/* PC-state VM that computes an alternating-sign u16 word sum:
 *   r = +w0 - w1 + w2 - w3 over n = (x & 3) + 1 words
 * with r kept as a signed i64 accumulator and returned as u64.
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0; sign = 1;
 *   while (n) {
 *     r += sign * (s & 0xFFFF);
 *     s >>= 16;
 *     sign = -sign;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_altwordsum64_loop_target.
 *
 * Distinct from:
 *   - vm_altbytesum64_loop  (byte stride, 8 states)
 *   - vm_signed_word_sum64_loop (sext-i16 add without sign flip)
 *
 * Tests: signed accumulator, sign flip per iteration via negation,
 * signed-times-zext-u16 multiply at 16-bit word stride.
 */
#include <stdio.h>
#include <stdint.h>

enum AwVmPc {
    AW_LOAD_N    = 0,
    AW_INIT_REGS = 1,
    AW_CHECK     = 2,
    AW_ACC       = 3,
    AW_SHIFT     = 4,
    AW_FLIP      = 5,
    AW_DEC       = 6,
    AW_HALT      = 7,
};

__declspec(noinline)
uint64_t vm_altwordsum64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    int64_t  r    = 0;
    int64_t  sign = 1;
    int      pc   = AW_LOAD_N;

    while (1) {
        if (pc == AW_LOAD_N) {
            n = (x & 3ull) + 1ull;
            pc = AW_INIT_REGS;
        } else if (pc == AW_INIT_REGS) {
            s    = x;
            r    = 0;
            sign = 1;
            pc = AW_CHECK;
        } else if (pc == AW_CHECK) {
            pc = (n > 0ull) ? AW_ACC : AW_HALT;
        } else if (pc == AW_ACC) {
            r = r + sign * (int64_t)(s & 0xFFFFull);
            pc = AW_SHIFT;
        } else if (pc == AW_SHIFT) {
            s = s >> 16;
            pc = AW_FLIP;
        } else if (pc == AW_FLIP) {
            sign = -sign;
            pc = AW_DEC;
        } else if (pc == AW_DEC) {
            n = n - 1ull;
            pc = AW_CHECK;
        } else if (pc == AW_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_altwordsum64(0x0001000200030004)=%llu\n",
           (unsigned long long)vm_altwordsum64_loop_target(0x0001000200030004ull));
    return 0;
}
