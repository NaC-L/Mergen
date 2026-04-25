/* PC-state VM that XOR-folds u32 dwords over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r ^ (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_xorfold64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_addchain64_loop (ADD)
 *   - vm_dword_subchain64_loop (SUB)
 *   - vm_dword_orfold64_loop   (OR)
 *   - vm_dword_andfold64_loop  (AND)
 *   - vm_dword_xormul64_loop   (XOR with multiply)
 *
 * Tests `xor i64` chain at 32-bit dword stride.  Pure XOR fold (no
 * multiply or shift mixing).
 */
#include <stdio.h>
#include <stdint.h>

enum DfVmPc {
    DF_INIT_ALL = 0,
    DF_CHECK    = 1,
    DF_BODY     = 2,
    DF_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_xorfold64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DF_INIT_ALL;

    while (1) {
        if (pc == DF_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DF_CHECK;
        } else if (pc == DF_CHECK) {
            pc = (n > 0ull) ? DF_BODY : DF_HALT;
        } else if (pc == DF_BODY) {
            r = r ^ (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DF_CHECK;
        } else if (pc == DF_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_xorfold64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_xorfold64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
