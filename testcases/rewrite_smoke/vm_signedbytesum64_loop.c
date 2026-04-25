/* PC-state VM that sums bytes interpreted as signed int8_t into an i64
 * accumulator over n = (x & 7) + 1 bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     int8_t sb = (int8_t)(s & 0xFF);   // sext i8 -> i64
 *     r += (int64_t)sb;
 *     s >>= 8;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signedbytesum64_loop_target.
 *
 * Distinct from vm_altbytesum64_loop (fixed alternating sign per
 * iteration): here every byte is sign-extended individually, so the
 * sign of each contribution is data-dependent on each byte's high bit.
 * Exercises i8 sext (not the i8 zext + neg pattern).  Bytes 0x00..0x7F
 * contribute +0..+127, bytes 0x80..0xFF contribute -128..-1.  Many
 * inputs produce negative i64 results that round-trip through u64.
 */
#include <stdio.h>
#include <stdint.h>

enum SbVmPc {
    SB_LOAD_N    = 0,
    SB_INIT_REGS = 1,
    SB_CHECK     = 2,
    SB_ACC       = 3,
    SB_SHIFT     = 4,
    SB_DEC       = 5,
    SB_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_signedbytesum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    int      pc = SB_LOAD_N;

    while (1) {
        if (pc == SB_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = SB_INIT_REGS;
        } else if (pc == SB_INIT_REGS) {
            s = x;
            r = 0;
            pc = SB_CHECK;
        } else if (pc == SB_CHECK) {
            pc = (n > 0ull) ? SB_ACC : SB_HALT;
        } else if (pc == SB_ACC) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r + (int64_t)sb;
            pc = SB_SHIFT;
        } else if (pc == SB_SHIFT) {
            s = s >> 8;
            pc = SB_DEC;
        } else if (pc == SB_DEC) {
            n = n - 1ull;
            pc = SB_CHECK;
        } else if (pc == SB_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_sgnbytesum64(0x7F7F7F7F7F7F7F7F)=%llu\n",
           (unsigned long long)vm_signedbytesum64_loop_target(0x7F7F7F7F7F7F7F7Full));
    return 0;
}
