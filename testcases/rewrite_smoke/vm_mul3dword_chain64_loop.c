/* PC-state VM that runs Horner-style hash with multiplier 3 over u32
 * dwords:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r * 3 + (s & 0xFFFFFFFF);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_mul3dword_chain64_loop_target.
 *
 * Distinct from:
 *   - vm_mul3word_chain64_loop  (16-bit lane stride, same multiplier 3)
 *   - vm_mul3byte_chain64_loop  (8-bit lane stride, same multiplier 3)
 *   - vm_dword_horner7_64_loop  (multiplier *7)
 *
 * Tests `mul i64 r, 3` (small-constant multiplier) at u32 dword stride.
 * Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum M3dVmPc {
    M3D_INIT_ALL = 0,
    M3D_CHECK    = 1,
    M3D_BODY     = 2,
    M3D_INC      = 3,
    M3D_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_mul3dword_chain64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = M3D_INIT_ALL;

    while (1) {
        if (pc == M3D_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = M3D_CHECK;
        } else if (pc == M3D_CHECK) {
            pc = (i < n) ? M3D_BODY : M3D_HALT;
        } else if (pc == M3D_BODY) {
            r = r * 3ull + (s & 0xFFFFFFFFull);
            s = s >> 32;
            pc = M3D_INC;
        } else if (pc == M3D_INC) {
            i = i + 1ull;
            pc = M3D_CHECK;
        } else if (pc == M3D_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_mul3dword_chain64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_mul3dword_chain64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
