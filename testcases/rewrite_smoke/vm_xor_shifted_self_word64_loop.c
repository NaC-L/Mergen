/* PC-state VM with self-shift XOR cross-feeding the u16 word stream:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((r >> 16) | ((s & 0xFFFF) << 48));
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_xor_shifted_self_word64_loop_target.
 *
 * Distinct from:
 *   - vm_xor_shifted_self_byte64_loop (8-bit lane stride)
 *   - vm_shiftin_top_word64_loop      (assigns (r>>16)|(word<<48), no XOR with r)
 *   - vm_xormulself_word64_loop       (mul-self with word, not shift-self)
 *
 * Tests `r XOR (r>>16 OR word<<48)` - self-shift used as XOR mask
 * combined with word injected at MSB position at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum XswVmPc {
    XSW_INIT_ALL = 0,
    XSW_CHECK    = 1,
    XSW_BODY     = 2,
    XSW_INC      = 3,
    XSW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xor_shifted_self_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XSW_INIT_ALL;

    while (1) {
        if (pc == XSW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = XSW_CHECK;
        } else if (pc == XSW_CHECK) {
            pc = (i < n) ? XSW_BODY : XSW_HALT;
        } else if (pc == XSW_BODY) {
            r = r ^ ((r >> 16) | ((s & 0xFFFFull) << 48));
            s = s >> 16;
            pc = XSW_INC;
        } else if (pc == XSW_INC) {
            i = i + 1ull;
            pc = XSW_CHECK;
        } else if (pc == XSW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xor_shifted_self_word64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xor_shifted_self_word64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
