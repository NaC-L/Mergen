/* PC-state VM that ADDs unsigned-u32 * counter into the accumulator
 * over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + (s & 0xFFFFFFFF) * (i + 1);   // u32 zext * counter, ADD-folded
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_uintadd_dword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_word_idx64_loop  (16-bit lane stride)
 *   - vm_uintadd_byte_idx64_loop  (8-bit lane stride)
 *   - vm_xormul_dword_idx64_loop  (XOR-folded counterpart at u32 stride)
 *
 * Tests unsigned dword (zext-i32) * counter ADD-folded into an i64
 * accumulator at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum UadVmPc {
    UAD_INIT_ALL = 0,
    UAD_CHECK    = 1,
    UAD_BODY     = 2,
    UAD_INC      = 3,
    UAD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_uintadd_dword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = UAD_INIT_ALL;

    while (1) {
        if (pc == UAD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = UAD_CHECK;
        } else if (pc == UAD_CHECK) {
            pc = (i < n) ? UAD_BODY : UAD_HALT;
        } else if (pc == UAD_BODY) {
            r = r + (s & 0xFFFFFFFFull) * (i + 1ull);
            s = s >> 32;
            pc = UAD_INC;
        } else if (pc == UAD_INC) {
            i = i + 1ull;
            pc = UAD_CHECK;
        } else if (pc == UAD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_uintadd_dword_idx64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_uintadd_dword_idx64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
