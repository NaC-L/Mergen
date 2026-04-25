/* PC-state VM that ADD-folds u16 words over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r + (s & 0xFFFF);
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_word_addchain64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_addchain64_loop (32-bit dword stride)
 *   - vm_word_orfold64_loop    (OR fold)
 *   - vm_word_andfold64_loop   (AND fold)
 *   - vm_signed_word_sum64_loop (sext-i16 add)
 *
 * Tests `add i64` chain at 16-bit word stride with zext-i16.  All-FF
 * input accumulates 4 * 0xFFFF = 262140.
 */
#include <stdio.h>
#include <stdint.h>

enum WcVmPc {
    WC_INIT_ALL = 0,
    WC_CHECK    = 1,
    WC_BODY     = 2,
    WC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_addchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WC_INIT_ALL;

    while (1) {
        if (pc == WC_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            pc = WC_CHECK;
        } else if (pc == WC_CHECK) {
            pc = (n > 0ull) ? WC_BODY : WC_HALT;
        } else if (pc == WC_BODY) {
            r = r + (s & 0xFFFFull);
            s = s >> 16;
            n = n - 1ull;
            pc = WC_CHECK;
        } else if (pc == WC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_addchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_word_addchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
