/* PC-state VM that ADD-folds u32 dwords over n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     r = r + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dword_addchain64_loop_target.
 *
 * Distinct from:
 *   - vm_dword_orfold64_loop  (OR fold, monotone)
 *   - vm_dword_xormul64_loop  (XOR with mul)
 *   - vm_dword_range64_loop   (umax/umin not add)
 *   - vm_signed_dword_sum64_loop (sext-i32 add, signed)
 *
 * Tests `add i64` chain at 32-bit dword stride with zext-i32.  Sum
 * can grow up to 2 * 0xFFFFFFFF = 0x1FFFFFFFE (33 bits) without u64
 * wrap.  Single-dword inputs return the low 32 bits of x.
 */
#include <stdio.h>
#include <stdint.h>

enum DcVmPc {
    DC_INIT_ALL = 0,
    DC_CHECK    = 1,
    DC_BODY     = 2,
    DC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_dword_addchain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DC_INIT_ALL;

    while (1) {
        if (pc == DC_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            pc = DC_CHECK;
        } else if (pc == DC_CHECK) {
            pc = (n > 0ull) ? DC_BODY : DC_HALT;
        } else if (pc == DC_BODY) {
            r = r + (s & 0xFFFFFFFFull);
            s = s >> 32;
            n = n - 1ull;
            pc = DC_CHECK;
        } else if (pc == DC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dword_addchain64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dword_addchain64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
