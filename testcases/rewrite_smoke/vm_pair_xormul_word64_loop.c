/* PC-state VM that processes consecutive u16 word pairs per iteration:
 *
 *   n = (x & 1) + 1;     // 1..2 pair iterations (up to 2 pairs of words)
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w0 = s & 0xFFFF;
 *     uint64_t w1 = (s >> 16) & 0xFFFF;
 *     r = r + (w0 ^ w1) * (w0 + w1);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_pair_xormul_word64_loop_target.
 *
 * Distinct from:
 *   - vm_pair_xormul_byte64_loop (byte pairs, 4 max iters)
 *   - vm_word_xormul64_loop      (single word per iter, no pair)
 *   - vm_xormul_word_idx64_loop  (single word * counter)
 *
 * Tests TWO word reads per iter (w0, w1 from s and s>>16) combined via
 * XOR (w0^w1) and ADD (w0+w1) then MULTIPLY together and ADD-folded.
 * Trip count uses & 1 so loop runs 1..2 times consuming 4 bytes each
 * iter at u16 lane width.
 */
#include <stdio.h>
#include <stdint.h>

enum PpwVmPc {
    PPW_INIT_ALL = 0,
    PPW_CHECK    = 1,
    PPW_BODY     = 2,
    PPW_INC      = 3,
    PPW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_pair_xormul_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = PPW_INIT_ALL;

    while (1) {
        if (pc == PPW_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = PPW_CHECK;
        } else if (pc == PPW_CHECK) {
            pc = (i < n) ? PPW_BODY : PPW_HALT;
        } else if (pc == PPW_BODY) {
            uint64_t w0 = s & 0xFFFFull;
            uint64_t w1 = (s >> 16) & 0xFFFFull;
            r = r + (w0 ^ w1) * (w0 + w1);
            s = s >> 32;
            pc = PPW_INC;
        } else if (pc == PPW_INC) {
            i = i + 1ull;
            pc = PPW_CHECK;
        } else if (pc == PPW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pair_xormul_word64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_pair_xormul_word64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
