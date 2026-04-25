/* PC-state VM that AND-folds u32 dwords over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0xFFFFFFFF;
 *   while (n) {
 *     r = r & (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_andfold64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_andfold64_loop (8-bit AND-fold)
 *   - vm_word_andfold64_loop (16-bit AND-fold)
 *   - vm_dword_orfold64_loop (OR-fold counterpart)
 *
 * Completes the AND-fold/OR-fold coverage matrix (3 widths x 2 ops).
 * Tests `and i64` chain at 32-bit dword stride.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_andfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0xFFFFFFFFull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (n > 0ull) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            r = r & (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_andfold64(0xFFFFFFFEFFFFFFFD)=%llu\n",
           (unsigned long long)vm_dword_andfold64_loop_target(0xFFFFFFFEFFFFFFFDull));
    return 0;
}
