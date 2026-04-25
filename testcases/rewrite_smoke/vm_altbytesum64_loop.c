/* PC-state VM that computes an alternating-sign byte sum:
 *   r = +b0 - b1 + b2 - b3 + ... over n = (x & 15) + 1 bytes
 * with r kept as a signed i64 accumulator and returned as u64.
 *
 *   n = (x & 15) + 1;
 *   s = x; r = 0; sign = 1;
 *   while (n) {
 *     r += sign * (s & 0xFF);
 *     s >>= 8;
 *     sign = -sign;
 *     n--;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_altbytesum64_loop_target.
 *
 * Distinct from vm_xorbytes64 (XOR of bytes) and vm_byteparity64 (1-bit
 * parity).  Tests: signed accumulator, sign flip per iteration via
 * negation, and signed-times-unsigned multiply.  Produces negative
 * (i64) values for inputs where the odd-indexed bytes dominate.
 */
#include <stdio.h>
#include <stdint.h>

enum AbVmPc {
    AB_LOAD_N    = 0,
    AB_INIT_REGS = 1,
    AB_CHECK     = 2,
    AB_ACC       = 3,
    AB_SHIFT     = 4,
    AB_FLIP      = 5,
    AB_DEC       = 6,
    AB_HALT      = 7,
};

__declspec(noinline)
uint64_t vm_altbytesum64_loop_target(uint64_t x) {
    uint64_t n    = 0;
    uint64_t s    = 0;
    int64_t  r    = 0;
    int64_t  sign = 1;
    int      pc   = AB_LOAD_N;

    while (1) {
        if (pc == AB_LOAD_N) {
            n = (x & 15ull) + 1ull;
            pc = AB_INIT_REGS;
        } else if (pc == AB_INIT_REGS) {
            s    = x;
            r    = 0;
            sign = 1;
            pc = AB_CHECK;
        } else if (pc == AB_CHECK) {
            pc = (n > 0ull) ? AB_ACC : AB_HALT;
        } else if (pc == AB_ACC) {
            r = r + sign * (int64_t)(s & 0xFFull);
            pc = AB_SHIFT;
        } else if (pc == AB_SHIFT) {
            s = s >> 8;
            pc = AB_FLIP;
        } else if (pc == AB_FLIP) {
            sign = -sign;
            pc = AB_DEC;
        } else if (pc == AB_DEC) {
            n = n - 1ull;
            pc = AB_CHECK;
        } else if (pc == AB_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_altbytesum64(0x0102030405060708)=%llu\n",
           (unsigned long long)vm_altbytesum64_loop_target(0x0102030405060708ull));
    return 0;
}
