/* PC-state VM running a dynamic-amount ASHR (signed shift right) and
 * XOR-fold of the low u32 dword over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     int64_t sx = (int64_t)x >> i;
 *     r = r ^ ((uint64_t)sx & 0xFFFFFFFF);
 *   }
 *   return r;
 *
 * Lift target: vm_dyn_ashr_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_dyn_ashr_word64_loop (16-bit window)
 *   - vm_dyn_ashr64_loop      (8-bit window)
 *
 * Wider 32-bit window of the moving signed shift at u32 mask.
 */
#include <stdio.h>
#include <stdint.h>

enum DadVmPc {
    DAD3_INIT_ALL = 0,
    DAD3_CHECK    = 1,
    DAD3_BODY     = 2,
    DAD3_INC      = 3,
    DAD3_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dyn_ashr_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DAD3_INIT_ALL;

    while (1) {
        if (pc == DAD3_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = DAD3_CHECK;
        } else if (pc == DAD3_CHECK) {
            pc = (i < n) ? DAD3_BODY : DAD3_HALT;
        } else if (pc == DAD3_BODY) {
            int64_t sx = (int64_t)x >> (int)i;
            r = r ^ ((uint64_t)sx & 0xFFFFFFFFull);
            pc = DAD3_INC;
        } else if (pc == DAD3_INC) {
            i = i + 1ull;
            pc = DAD3_CHECK;
        } else if (pc == DAD3_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dyn_ashr_dword64(0xDEADBEEFCAFEBABE)=%llu\n",
           (unsigned long long)vm_dyn_ashr_dword64_loop_target(0xDEADBEEFCAFEBABEull));
    return 0;
}
