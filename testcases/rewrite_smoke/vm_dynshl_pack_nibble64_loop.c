/* PC-state VM that XOR-packs 4-bit nibbles of x into r at DYNAMIC bit
 * positions controlled by the loop index:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xF) << i);   // dynamic shl by i, 4-bit chunk
 *     s >>= 4;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_pack_nibble64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop (2-bit chunks)
 *   - vm_byteshl3_xor64_loop (8-bit chunks placed at 3-bit stride)
 *   - vm_nibrev_window64_loop (nibble pack at 4-bit stride, no XOR)
 *
 * 4-bit chunk source with single-bit (per-iter) stride; chunks
 * overlap heavily, exercising shl-by-counter on a wider mask.
 */
#include <stdio.h>
#include <stdint.h>

enum DsnVmPc {
    DSN_INIT_ALL = 0,
    DSN_CHECK    = 1,
    DSN_BODY     = 2,
    DSN_INC      = 3,
    DSN_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_pack_nibble64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DSN_INIT_ALL;

    while (1) {
        if (pc == DSN_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DSN_CHECK;
        } else if (pc == DSN_CHECK) {
            pc = (i < n) ? DSN_BODY : DSN_HALT;
        } else if (pc == DSN_BODY) {
            r = r ^ ((s & 0xFull) << i);
            s = s >> 4;
            pc = DSN_INC;
        } else if (pc == DSN_INC) {
            i = i + 1ull;
            pc = DSN_CHECK;
        } else if (pc == DSN_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_pack_nibble64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_dynshl_pack_nibble64_loop_target(0xCAFEBABEull));
    return 0;
}
