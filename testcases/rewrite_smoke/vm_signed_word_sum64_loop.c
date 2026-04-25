/* PC-state VM that sums sext-i16 words per iteration:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     r = r + (int64_t)sw;     // sext i16 -> i64
 *     s >>= 16;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_signed_word_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_signedbytesum64_loop (sext-i8 byte sum, 8-bit stride)
 *   - vm_signed_dword_sum64_loop (sext-i32 dword sum, 32-bit stride)
 *
 * Fills the i16 middle width and completes the sext-width trio
 * (i8/i16/i32 -> i64).  Word-stride consumption with high-bit-set
 * words sign-extending to negative i64.
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
uint64_t vm_signed_word_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = SW_INIT_ALL;

    while (1) {
        if (pc == SW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = SW_CHECK;
        } else if (pc == SW_CHECK) {
            pc = (i < n) ? SW_BODY : SW_HALT;
        } else if (pc == SW_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            r = r + (int64_t)sw;
            s = s >> 16;
            pc = SW_INC;
        } else if (pc == SW_INC) {
            i = i + 1ull;
            pc = SW_CHECK;
        } else if (pc == SW_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signed_word_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_signed_word_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
