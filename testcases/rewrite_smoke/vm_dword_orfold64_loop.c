/* PC-state VM that OR-folds u32 dwords over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r | (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_orfold64_loop_target.
 *
 * Distinct from:
 *   - vm_word_orfold64_loop  (u16 OR-fold, 16-bit stride)
 *   - vm_dword_xormul64_loop (dword XOR with mul)
 *   - vm_dword_range64_loop  (umax/umin not OR-fold)
 *
 * Tests `or i64` chain at 32-bit dword stride.  Monotone OR-fold
 * (only sets bits) on dword chunks.  Single-dword inputs return
 * the low 32 bits of x.
 */
#include <stdio.h>
#include <stdint.h>

enum DoVmPc {
    DO_INIT_ALL = 0,
    DO_CHECK    = 1,
    DO_BODY     = 2,
    DO_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_orfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DO_INIT_ALL;

    while (1) {
        if (pc == DO_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DO_CHECK;
        } else if (pc == DO_CHECK) {
            pc = (n > 0ull) ? DO_BODY : DO_HALT;
        } else if (pc == DO_BODY) {
            r = r | (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DO_CHECK;
        } else if (pc == DO_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_orfold64(0xFEDCBA9876543210)=%llu\n",
           (unsigned long long)vm_dword_orfold64_loop_target(0xFEDCBA9876543210ull));
    return 0;
}
