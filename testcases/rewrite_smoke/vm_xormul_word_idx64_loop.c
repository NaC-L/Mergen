/* PC-state VM that XORs scaled u16 words into the accumulator across
 * n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFFFF) * (i + 1));   // unsigned word * counter
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_xormul_word_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop (8-bit lane stride)
 *   - vm_word_xormul64_loop     (per-lane self-multiply, no counter scale)
 *
 * Tests unsigned word (zext-i16) multiplied by dynamic counter (i+1)
 * folded into the accumulator via XOR.  Each lane is scaled by a
 * different counter, so byte values do not collapse.
 */
#include <stdio.h>
#include <stdint.h>

enum XwVmPc {
    XW_INIT_ALL = 0,
    XW_CHECK    = 1,
    XW_BODY     = 2,
    XW_INC      = 3,
    XW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormul_word_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XW_INIT_ALL;

    while (1) {
        if (pc == XW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XW_CHECK;
        } else if (pc == XW_CHECK) {
            pc = (i < n) ? XW_BODY : XW_HALT;
        } else if (pc == XW_BODY) {
            r = r ^ ((s & 0xFFFFull) * (i + 1ull));
            s = s >> 16;
            pc = XW_INC;
        } else if (pc == XW_INC) {
            i = i + 1ull;
            pc = XW_CHECK;
        } else if (pc == XW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormul_word_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormul_word_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
