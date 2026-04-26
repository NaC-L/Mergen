/* PC-state VM that ADDs (sext-i16 word) * counter into the accumulator
 * over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int16_t sw = (int16_t)(s & 0xFFFF);
 *     r = r + (int64_t)sw * (int64_t)(i + 1);
 *     s >>= 16;
 *   }
 *   return (uint64_t)r;
 *
 * Lift target: vm_wordsmul_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop      (8-bit lane, signed sext + ADD)
 *   - vm_uintadd_word_idx64_loop  (zext-i16 ADD counterpart at u16 stride)
 *
 * Tests sext-i16 word * counter ADD-folded into i64 accumulator at u16
 * stride.  Lanes with high-bit set (>=0x8000) contribute negatively.
 */
#include <stdio.h>
#include <stdint.h>

enum WsmVmPc {
    WSM_INIT_ALL = 0,
    WSM_CHECK    = 1,
    WSM_BODY     = 2,
    WSM_INC      = 3,
    WSM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordsmul_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    int64_t  r  = 0;
    uint64_t i  = 0;
    int      pc = WSM_INIT_ALL;

    while (1) {
        if (pc == WSM_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0;
            i = 0ull;
            pc = WSM_CHECK;
        } else if (pc == WSM_CHECK) {
            pc = (i < n) ? WSM_BODY : WSM_HALT;
        } else if (pc == WSM_BODY) {
            int16_t sw = (int16_t)(s & 0xFFFFull);
            r = r + (int64_t)sw * (int64_t)(i + 1ull);
            s = s >> 16;
            pc = WSM_INC;
        } else if (pc == WSM_INC) {
            i = i + 1ull;
            pc = WSM_CHECK;
        } else if (pc == WSM_HALT) {
            return (uint64_t)r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordsmul_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_wordsmul_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
