/* PC-state VM that XORs scaled u32 dwords into the accumulator across
 * n = (x & 1) + 1 iterations:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFFFFFFFF) * (i + 1));   // unsigned dword * counter
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_xormul_dword_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_word_idx64_loop (16-bit lane stride)
 *   - vm_xormul_byte_idx64_loop (8-bit lane stride)
 *   - vm_dword_xormul64_loop    (per-lane self-multiply, no counter scale)
 *
 * Tests unsigned dword (zext-i32) multiplied by dynamic counter (i+1)
 * folded into the accumulator via XOR.  Trip count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum XdVmPc {
    XD_INIT_ALL = 0,
    XD_CHECK    = 1,
    XD_BODY     = 2,
    XD_INC      = 3,
    XD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormul_dword_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XD_INIT_ALL;

    while (1) {
        if (pc == XD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XD_CHECK;
        } else if (pc == XD_CHECK) {
            pc = (i < n) ? XD_BODY : XD_HALT;
        } else if (pc == XD_BODY) {
            r = r ^ ((s & 0xFFFFFFFFull) * (i + 1ull));
            s = s >> 32;
            pc = XD_INC;
        } else if (pc == XD_INC) {
            i = i + 1ull;
            pc = XD_CHECK;
        } else if (pc == XD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormul_dword_idx64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xormul_dword_idx64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
