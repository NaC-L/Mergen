/* PC-state VM that finds the maximum u32 dword value across the lower
 * n dwords of x where n = (x & 1) + 1.  Pure unsigned compare-driven
 * max-update.
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint32_t d = s & 0xFFFFFFFF;
 *     if (d > r) r = d;
 *     s >>= 32;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordmax64_loop_target.
 *
 * Distinct from:
 *   - vm_wordmax64_loop  (16-bit stride)
 *   - vm_bytemax64_loop  (8-bit stride)
 *   - vm_dword_addchain64_loop (sum, no max)
 *
 * Tests u32 cmp + select-style update where the "no-update" path keeps
 * the running max unchanged at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum DmVmPc {
    DM_LOAD_N    = 0,
    DM_INIT_REGS = 1,
    DM_CHECK     = 2,
    DM_BODY      = 3,
    DM_SHIFT     = 4,
    DM_DEC       = 5,
    DM_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_dwordmax64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = DM_LOAD_N;

    while (1) {
        if (pc == DM_LOAD_N) {
            n = (x & 1ull) + 1ull;
            pc = DM_INIT_REGS;
        } else if (pc == DM_INIT_REGS) {
            s = x;
            r = 0ull;
            pc = DM_CHECK;
        } else if (pc == DM_CHECK) {
            pc = (n > 0ull) ? DM_BODY : DM_HALT;
        } else if (pc == DM_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = (d > r) ? d : r;
            pc = DM_SHIFT;
        } else if (pc == DM_SHIFT) {
            s = s >> 32;
            pc = DM_DEC;
        } else if (pc == DM_DEC) {
            n = n - 1ull;
            pc = DM_CHECK;
        } else if (pc == DM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordmax64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_dwordmax64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
