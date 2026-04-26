/* PC-state VM that XORs each u32 dword shifted left by (i*3) bits into r:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFFFFFFFF) << (i * 3));   // dynamic shl by 3*i
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordshl3_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_wordshl3_xor64_loop  (16-bit stride)
 *   - vm_byteshl3_xor64_loop  (8-bit stride)
 *   - vm_dword_xormul64_loop  (per-lane self-mul XOR-fold, no shl)
 *
 * Tests `shl i64 dword, %i*3` (dynamic shl by counter expression) at
 * u32 stride.  Trip count <= 2, so shifts are 0 and 3.
 */
#include <stdio.h>
#include <stdint.h>

enum DshxVmPc {
    DSHX_INIT_ALL = 0,
    DSHX_CHECK    = 1,
    DSHX_BODY     = 2,
    DSHX_INC      = 3,
    DSHX_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordshl3_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSHX_INIT_ALL;

    while (1) {
        if (pc == DSHX_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DSHX_CHECK;
        } else if (pc == DSHX_CHECK) {
            pc = (i < n) ? DSHX_BODY : DSHX_HALT;
        } else if (pc == DSHX_BODY) {
            r = r ^ ((s & 0xFFFFFFFFull) << (i * 3ull));
            s = s >> 32;
            pc = DSHX_INC;
        } else if (pc == DSHX_INC) {
            i = i + 1ull;
            pc = DSHX_CHECK;
        } else if (pc == DSHX_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordshl3_xor64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dwordshl3_xor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
