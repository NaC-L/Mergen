/* PC-state VM that AND-folds u8 bytes over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0xFF;
 *   while (n) {
 *     r = r & (s & 0xFF);
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_andfold64_loop_target.
 *
 * Distinct from:
 *   - vm_andsum_byte_idx64_loop (byte AND counter, ADD-folded)
 *   - vm_word_orfold64_loop     (OR fold, monotone INCREASING)
 *   - vm_byteprod64_loop        (multiplicative chain)
 *
 * Tests `and i64` chain at byte stride.  AND fold is monotone
 * DECREASING (only clears bits) - counterpart to OR's monotone
 * increasing.  Any zero byte clears the accumulator to 0.  All-FF
 * input preserves r=0xFF.
 */
#include <stdio.h>
#include <stdint.h>

enum BaVmPc {
    BA_INIT_ALL = 0,
    BA_CHECK    = 1,
    BA_BODY     = 2,
    BA_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_andfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BA_INIT_ALL;

    while (1) {
        if (pc == BA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0xFFull;
            pc = BA_CHECK;
        } else if (pc == BA_CHECK) {
            pc = (n > 0ull) ? BA_BODY : BA_HALT;
        } else if (pc == BA_BODY) {
            r = r & (s & 0xFFull);
            s = s >> 8;
            n = n - 1ull;
            pc = BA_CHECK;
        } else if (pc == BA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_andfold64(0xFFFEFDFCFBFAF9F8)=%llu\n",
           (unsigned long long)vm_byte_andfold64_loop_target(0xFFFEFDFCFBFAF9F8ull));
    return 0;
}
