/* PC-state VM with self-shift XOR cross-feeding the u32 dword stream:
 *
 *   n = (x & 1) + 1;
 *   s = x; r = x;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((r >> 32) | ((s & 0xFFFFFFFF) << 32));
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_xor_shifted_self_dword64_loop_target.
 *
 * Distinct from:
 *   - vm_xor_shifted_self_word64_loop (16-bit stride)
 *   - vm_xor_shifted_self_byte64_loop (8-bit stride)
 *   - vm_shiftin_top_dword64_loop     (assigns shifted form, no XOR with r)
 *
 * Tests `r XOR (r>>32 OR dword<<32)` - self-shift used as XOR mask
 * combined with dword injected at MSB position at u32 stride.  Trip
 * count <= 2.
 */
#include <stdio.h>
#include <stdint.h>

enum XsdVmPc {
    XSD_INIT_ALL = 0,
    XSD_CHECK    = 1,
    XSD_BODY     = 2,
    XSD_INC      = 3,
    XSD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xor_shifted_self_dword64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XSD_INIT_ALL;

    while (1) {
        if (pc == XSD_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = x;
            i = 0ull;
            pc = XSD_CHECK;
        } else if (pc == XSD_CHECK) {
            pc = (i < n) ? XSD_BODY : XSD_HALT;
        } else if (pc == XSD_BODY) {
            r = r ^ ((r >> 32) | ((s & 0xFFFFFFFFull) << 32));
            s = s >> 32;
            pc = XSD_INC;
        } else if (pc == XSD_INC) {
            i = i + 1ull;
            pc = XSD_CHECK;
        } else if (pc == XSD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xor_shifted_self_dword64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xor_shifted_self_dword64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
