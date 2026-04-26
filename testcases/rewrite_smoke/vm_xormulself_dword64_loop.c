/* PC-state VM with self-referential multiply per iter at u32 stride:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t d = s & 0xFFFFFFFF;
 *     r = r ^ (d * (r + 1));   // r appears in mul operand
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_xormulself_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_xormulself_word64_loop (16-bit lane stride)
 *   - vm_xormulself_byte64_loop (8-bit lane stride)
 *   - vm_xormul_dword_idx64_loop (lane * counter, no self-ref)
 *
 * Tests `mul i64 dword, (r+1)` where the multiplier operand is the
 * accumulator+1 (self-reference) at u32 stride.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum XmdVmPc {
    XMD_INIT_ALL = 0,
    XMD_CHECK    = 1,
    XMD_BODY     = 2,
    XMD_INC      = 3,
    XMD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulself_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XMD_INIT_ALL;

    while (1) {
        if (pc == XMD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XMD_CHECK;
        } else if (pc == XMD_CHECK) {
            pc = (i < n) ? XMD_BODY : XMD_HALT;
        } else if (pc == XMD_BODY) {
            uint64_t d = s & 0xFFFFFFFFull;
            r = r ^ (d * (r + 1ull));
            s = s >> 32;
            pc = XMD_INC;
        } else if (pc == XMD_INC) {
            i = i + 1ull;
            pc = XMD_CHECK;
        } else if (pc == XMD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulself_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xormulself_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
