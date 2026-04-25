/* PC-state VM that runs Horner-style hash on u16 words with mul 13:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r * 13 + w;     // Horner on words
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_word_horner13_64_loop_target.
 *
 * Distinct from:
 *   - vm_mul3byte_chain64_loop (Horner on BYTES with mul 3)
 *   - vm_djb264_loop          (Horner on bytes with mul 33)
 *   - vm_word_xormul64_loop   (word self-multiply XOR)
 *   - vm_horner64_loop        (general polynomial)
 *
 * Tests Horner-style multiply-then-add chain on 16-bit word reads
 * (stride 16 bits) with multiplier 13.  Different stride width AND
 * different multiplier than existing byte-Horner samples.
 */
#include <stdio.h>
#include <stdint.h>

enum WhVmPc {
    WH_INIT_ALL = 0,
    WH_CHECK    = 1,
    WH_BODY     = 2,
    WH_INC      = 3,
    WH_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_word_horner13_64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WH_INIT_ALL;

    while (1) {
        if (pc == WH_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = WH_CHECK;
        } else if (pc == WH_CHECK) {
            pc = (i < n) ? WH_BODY : WH_HALT;
        } else if (pc == WH_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r * 13ull + w;
            s = s >> 16;
            pc = WH_INC;
        } else if (pc == WH_INC) {
            i = i + 1ull;
            pc = WH_CHECK;
        } else if (pc == WH_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_horner13_64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_horner13_64_loop_target(0xCAFEBABEull));
    return 0;
}
