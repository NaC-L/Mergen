/* PC-state VM that AND-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0xFFFF;
 *   while (n) {
 *     r = r & (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_andfold64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_andfold64_loop (8-bit AND-fold)
 *   - vm_word_orfold64_loop  (OR-fold counterpart)
 *
 * Tests `and i64` chain at 16-bit word stride.  Monotone DECREASING
 * AND-fold (only clears bits).  Single-word inputs return the word
 * value (since r starts at 0xFFFF and AND with that word stays).
 */
#include <stdio.h>
#include <stdint.h>

enum WaVmPc {
    WA_INIT_ALL = 0,
    WA_CHECK    = 1,
    WA_BODY     = 2,
    WA_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_andfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WA_INIT_ALL;

    while (1) {
        if (pc == WA_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0xFFFFull;
            pc = WA_CHECK;
        } else if (pc == WA_CHECK) {
            pc = (n > 0ull) ? WA_BODY : WA_HALT;
        } else if (pc == WA_BODY) {
            r = r & (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WA_CHECK;
        } else if (pc == WA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_andfold64(0xFFFFFFFFFFFFFFF8)=%llu\n",
           (unsigned long long)vm_word_andfold64_loop_target(0xFFFFFFFFFFFFFFF8ull));
    return 0;
}
