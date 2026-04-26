/* PC-state VM that XORs each u16 word shifted left by (i*3) bits into r:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFFFF) << (i * 3));   // dynamic shl by 3*i
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordshl3_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_byteshl3_xor64_loop  (8-bit stride)
 *   - vm_word_xormul64_loop   (per-lane self-mul XOR-fold, no shl)
 *
 * Tests `shl i64 word, %i*3` (dynamic shl by counter expression) at u16
 * stride.  i ranges 0..3, so shifts are 0/3/6/9.
 */
#include <stdio.h>
#include <stdint.h>

enum WshxVmPc {
    WSHX_INIT_ALL = 0,
    WSHX_CHECK    = 1,
    WSHX_BODY     = 2,
    WSHX_INC      = 3,
    WSHX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordshl3_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WSHX_INIT_ALL;

    while (1) {
        if (pc == WSHX_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WSHX_CHECK;
        } else if (pc == WSHX_CHECK) {
            pc = (i < n) ? WSHX_BODY : WSHX_HALT;
        } else if (pc == WSHX_BODY) {
            r = r ^ ((s & 0xFFFFull) << (i * 3ull));
            s = s >> 16;
            pc = WSHX_INC;
        } else if (pc == WSHX_INC) {
            i = i + 1ull;
            pc = WSHX_CHECK;
        } else if (pc == WSHX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordshl3_xor64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_wordshl3_xor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
