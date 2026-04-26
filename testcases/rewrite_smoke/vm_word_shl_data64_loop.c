/* PC-state VM with DATA-DEPENDENT shift amount inside the loop body
 * at u16 word stride:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = (r << (w & 15)) | (w >> 8);   // shl amount comes from word data
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_word_shl_data64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl_data64_loop  (byte stride, 3-bit shift mask, OR with byte high nibble)
 *   - vm_dynshl_accum_word64_loop (counter-derived shift amount)
 *
 * Tests `shl i64 r, %word_amount` (data-derived 4-bit shift amount)
 * combined with OR of word's high byte at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WshdVmPc {
    WSHD_INIT_ALL = 0,
    WSHD_CHECK    = 1,
    WSHD_BODY     = 2,
    WSHD_INC      = 3,
    WSHD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_shl_data64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WSHD_INIT_ALL;

    while (1) {
        if (pc == WSHD_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WSHD_CHECK;
        } else if (pc == WSHD_CHECK) {
            pc = (i < n) ? WSHD_BODY : WSHD_HALT;
        } else if (pc == WSHD_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = (r << (w & 15ull)) | (w >> 8);
            s = s >> 16;
            pc = WSHD_INC;
        } else if (pc == WSHD_INC) {
            i = i + 1ull;
            pc = WSHD_CHECK;
        } else if (pc == WSHD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_shl_data64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_word_shl_data64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
