/* PC-state VM that OR-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r | (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_orfold64_loop_target.
 *
 * Distinct from:
 *   - vm_orsum_byte_idx64_loop (byte | counter, 8-bit stride)
 *   - vm_word_xormul64_loop    (word self-multiply XOR fold)
 *   - vm_word_horner13_64_loop (word Horner with mul 13)
 *
 * Tests `or i64` chain at 16-bit word stride.  OR is monotone (only
 * sets bits), so result is bitwise-OR of all consumed words.  4
 * stateful slots (n,s,r + implicit) with n-decrement loop control.
 */
#include <stdio.h>
#include <stdint.h>

enum WoVmPc {
    WO_INIT_ALL = 0,
    WO_CHECK    = 1,
    WO_BODY     = 2,
    WO_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_orfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WO_INIT_ALL;

    while (1) {
        if (pc == WO_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WO_CHECK;
        } else if (pc == WO_CHECK) {
            pc = (n > 0ull) ? WO_BODY : WO_HALT;
        } else if (pc == WO_BODY) {
            r = r | (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WO_CHECK;
        } else if (pc == WO_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_orfold64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_orfold64_loop_target(0xCAFEBABEull));
    return 0;
}
