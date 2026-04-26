/* PC-state VM that XOR-packs 8-bit bytes of x into r at DYNAMIC bit
 * positions controlled by the loop index:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) << i);   // dynamic shl by i, 8-bit chunk
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_pack_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop        (2-bit chunks)
 *   - vm_dynshl_pack_nibble64_loop (4-bit chunks)
 *   - vm_byteshl3_xor64_loop       (8-bit chunks at 3-bit stride, not 1-bit)
 *
 * 8-bit chunk source with single-bit per-iter stride; chunks overlap
 * heavily.
 */
#include <stdio.h>
#include <stdint.h>

enum DsbVmPc {
    DSB_INIT_ALL = 0,
    DSB_CHECK    = 1,
    DSB_BODY     = 2,
    DSB_INC      = 3,
    DSB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_pack_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSB_INIT_ALL;

    while (1) {
        if (pc == DSB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DSB_CHECK;
        } else if (pc == DSB_CHECK) {
            pc = (i < n) ? DSB_BODY : DSB_HALT;
        } else if (pc == DSB_BODY) {
            r = r ^ ((s & 0xFFull) << i);
            s = s >> 8;
            pc = DSB_INC;
        } else if (pc == DSB_INC) {
            i = i + 1ull;
            pc = DSB_CHECK;
        } else if (pc == DSB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_pack_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dynshl_pack_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
