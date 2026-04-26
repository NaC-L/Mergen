/* PC-state VM that XORs (sext-i16 word * counter) into the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     r = r ^ (uint64_t)((int64_t)sw * (int64_t)(i + 1));
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_signedxor_word_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_signedxor_byte_idx64_loop (8-bit lane stride)
 *   - vm_xormul_word_idx64_loop    (zext-i16 XOR counterpart)
 *
 * Tests sext-i16 word * counter XOR-folded into i64 accumulator at u16
 * stride.  Negative lanes produce sign-extended scaled values that
 * differ from the zext path.
 */
#include <stdio.h>
#include <stdint.h>

enum SwVmPc {
    SW_INIT_ALL = 0,
    SW_CHECK    = 1,
    SW_BODY     = 2,
    SW_INC      = 3,
    SW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signedxor_word_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SW_INIT_ALL;

    while (1) {
        if (pc == SW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SW_CHECK;
        } else if (pc == SW_CHECK) {
            pc = (i < n) ? SW_BODY : SW_HALT;
        } else if (pc == SW_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            r = r ^ (uint64_t)((int64_t)sw * (int64_t)(i + 1ull));
            s = s >> 16;
            pc = SW_INC;
        } else if (pc == SW_INC) {
            i = i + 1ull;
            pc = SW_CHECK;
        } else if (pc == SW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedxor_word_idx64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_signedxor_word_idx64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
