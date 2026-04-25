/* PC-state VM that XOR-folds SIGNED bytes scaled by counter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     int8_t sb = (int8_t)(s & 0xFF);
 *     r = r ^ (uint64_t)((int64_t)sb * (int64_t)(i + 1));
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_signedxor_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (UNSIGNED zext byte * counter, XOR-folded)
 *   - vm_bytesmul_idx64_loop     (signed sext byte * counter, ADD-folded)
 *
 * Fills the sext+XOR cell of the per-byte * counter matrix.  For
 * positive bytes (high bit clear) sext == zext so XOR is identical to
 * the unsigned variant; for negative bytes (>= 0x80) the sign-extended
 * value populates the upper 56 bits with 1s, producing a different
 * fold pattern than the zext version.
 */
#include <stdio.h>
#include <stdint.h>

enum SbVmPc {
    SB_INIT_ALL = 0,
    SB_CHECK    = 1,
    SB_BODY     = 2,
    SB_INC      = 3,
    SB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_signedxor_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SB_INIT_ALL;

    while (1) {
        if (pc == SB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SB_CHECK;
        } else if (pc == SB_CHECK) {
            pc = (i < n) ? SB_BODY : SB_HALT;
        } else if (pc == SB_BODY) {
            int8_t sb = (int8_t)(s & 0xFFull);
            r = r ^ (uint64_t)((int64_t)sb * (int64_t)(i + 1ull));
            s = s >> 8;
            pc = SB_INC;
        } else if (pc == SB_INC) {
            i = i + 1ull;
            pc = SB_CHECK;
        } else if (pc == SB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_signedxor_byte_idx64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_signedxor_byte_idx64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
