/* PC-state VM that AND-accumulates u16 words >= 0x8000 (identity 0xFFFF):
 *
 *   n = (x & 3) + 1;
 *   s = x; acc = 0xFFFF;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     acc = acc & ((w >= 0x8000) ? w : 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return acc;
 *
 * Lift target: vm_word_and_uge_thresh64_loop_target.
 *
 * Predicate-gated AND accumulator at u16 stride (identity 0xFFFF).
 * Word-stride counterpart of vm_byte_and_uge_thresh64_loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WandVmPc {
    WAND_INIT_ALL = 0,
    WAND_CHECK    = 1,
    WAND_BODY     = 2,
    WAND_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_and_uge_thresh64_loop_target(uint64_t x) {
    uint64_t n   = 0;
    uint64_t s   = 0;
    uint64_t acc = 0;
    int      pc  = WAND_INIT_ALL;

    while (1) {
        if (pc == WAND_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            acc = 0xFFFFull;
            pc = WAND_CHECK;
        } else if (pc == WAND_CHECK) {
            pc = (n > 0ull) ? WAND_BODY : WAND_HALT;
        } else if (pc == WAND_BODY) {
            uint64_t w = s & 0xFFFFull;
            acc = acc & ((w >= 0x8000ull) ? w : 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WAND_CHECK;
        } else if (pc == WAND_HALT) {
            return acc;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_and_uge_thresh64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_and_uge_thresh64_loop_target(0xCAFEBABEull));
    return 0;
}
