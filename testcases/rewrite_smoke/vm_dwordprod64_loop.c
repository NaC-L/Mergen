/* PC-state VM that computes the running product of u32 dwords:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 1;
 *   for (i = 0; i < n; i++) {
 *     r = r * (s & 0xFFFFFFFF);    // u32 multiplicative chain (mod 2^64)
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_dwordprod64_loop_target.
 *
 * Distinct from:
 *   - vm_wordprod64_loop  (16-bit stride)
 *   - vm_byteprod64_loop  (8-bit stride)
 *   - vm_dword_xormul64_loop (per-dword self-multiply XOR-folded)
 *
 * Tests `mul i64 r, dword` chained across iterations at u32 stride.
 * Trip count <= 2; any zero dword in the loop collapses r to 0.
 */
#include <stdio.h>
#include <stdint.h>

enum DpVmPc {
    DP_INIT_ALL = 0,
    DP_CHECK    = 1,
    DP_BODY     = 2,
    DP_INC      = 3,
    DP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dwordprod64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DP_INIT_ALL;

    while (1) {
        if (pc == DP_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 1ull;
            i = 0ull;
            pc = DP_CHECK;
        } else if (pc == DP_CHECK) {
            pc = (i < n) ? DP_BODY : DP_HALT;
        } else if (pc == DP_BODY) {
            r = r * (s & 0xFFFFFFFFull);
            s = s >> 32;
            pc = DP_INC;
        } else if (pc == DP_INC) {
            i = i + 1ull;
            pc = DP_CHECK;
        } else if (pc == DP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dwordprod64(0x0000000200000003)=%llu\n",
           (unsigned long long)vm_dwordprod64_loop_target(0x0000000200000003ull));
    return 0;
}
