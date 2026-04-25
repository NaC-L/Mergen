/* PC-state VM that SUB-folds u32 dwords over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r - (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_subchain64_loop_target.
 *
 * Distinct from:
 *   - vm_word_subchain64_loop (16-bit SUB-fold)
 *   - vm_dword_addchain64_loop (ADD counterpart, same stride)
 *   - vm_subbyte_idx64_loop   (byte SUB chain)
 *
 * Tests `sub i64` chain at 32-bit dword stride.  Result wraps below
 * zero into u64 modular space.  All-FF sums to -2*0xFFFFFFFF wrapped.
 */
#include <stdio.h>
#include <stdint.h>

enum DsVmPc {
    DS_INIT_ALL = 0,
    DS_CHECK    = 1,
    DS_BODY     = 2,
    DS_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_subchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DS_INIT_ALL;

    while (1) {
        if (pc == DS_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DS_CHECK;
        } else if (pc == DS_CHECK) {
            pc = (n > 0ull) ? DS_BODY : DS_HALT;
        } else if (pc == DS_BODY) {
            r = r - (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DS_CHECK;
        } else if (pc == DS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_subchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_subchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
