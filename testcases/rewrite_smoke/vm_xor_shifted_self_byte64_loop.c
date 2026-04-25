/* PC-state VM with self-shift XOR cross-feeding the byte stream:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((r >> 8) | ((s & 0xFF) << 56));
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xor_shifted_self_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_shiftin_top64_loop      (assigns (r>>8)|(byte<<56), no XOR)
 *   - vm_xormulself_byte64_loop  (mul-self with byte, not shift-self)
 *   - vm_byterev_window64_loop   (shift register filling, no XOR)
 *
 * Tests `r XOR (r>>8 OR byte<<56)` - self-shift used as XOR mask
 * combined with byte injected at MSB position.  Each iter mixes
 * the running r with its lower 56 bits and a byte at the top.
 */
#include <stdio.h>
#include <stdint.h>

enum XsVmPc {
    XS_INIT_ALL = 0,
    XS_CHECK    = 1,
    XS_BODY     = 2,
    XS_INC      = 3,
    XS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xor_shifted_self_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XS_INIT_ALL;

    while (1) {
        if (pc == XS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = XS_CHECK;
        } else if (pc == XS_CHECK) {
            pc = (i < n) ? XS_BODY : XS_HALT;
        } else if (pc == XS_BODY) {
            r = r ^ ((r >> 8) | ((s & 0xFFull) << 56));
            s = s >> 8;
            pc = XS_INC;
        } else if (pc == XS_INC) {
            i = i + 1ull;
            pc = XS_CHECK;
        } else if (pc == XS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xor_shifted_self_byte64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_xor_shifted_self_byte64_loop_target(0xDEADBEEFull));
    return 0;
}
