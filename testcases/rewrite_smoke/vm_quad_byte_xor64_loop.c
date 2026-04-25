/* PC-state VM that processes 4 bytes per iteration (32-bit stride):
 *
 *   n = (x & 1) + 1;     // 1..2 quad iterations
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b0 = s & 0xFF;
 *     uint64_t b1 = (s >> 8) & 0xFF;
 *     uint64_t b2 = (s >> 16) & 0xFF;
 *     uint64_t b3 = (s >> 24) & 0xFF;
 *     r = r + (b0 ^ b1 ^ b2 ^ b3);
 *     s >>= 32;
 *   }
 *   return r;
 *
 * Lift target: vm_quad_byte_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_pair_xormul_byte64_loop (TWO bytes per iter)
 *   - All single-byte-per-iter samples
 *
 * Tests FOUR byte reads per iteration combined via 3 chained XORs
 * then ADD-folded into accumulator.  Wider 32-bit stride per iter
 * (advances s by 4 bytes).  Trip uses `& 1` so loop runs 1..2 times
 * consuming 4 bytes each.
 */
#include <stdio.h>
#include <stdint.h>

enum QbVmPc {
    QB_INIT_ALL = 0,
    QB_CHECK    = 1,
    QB_BODY     = 2,
    QB_INC      = 3,
    QB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_quad_byte_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = QB_INIT_ALL;

    while (1) {
        if (pc == QB_INIT_ALL) {
            n = (x & 1ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = QB_CHECK;
        } else if (pc == QB_CHECK) {
            pc = (i < n) ? QB_BODY : QB_HALT;
        } else if (pc == QB_BODY) {
            uint64_t b0 = s & 0xFFull;
            uint64_t b1 = (s >> 8) & 0xFFull;
            uint64_t b2 = (s >> 16) & 0xFFull;
            uint64_t b3 = (s >> 24) & 0xFFull;
            r = r + (b0 ^ b1 ^ b2 ^ b3);
            s = s >> 32;
            pc = QB_INC;
        } else if (pc == QB_INC) {
            i = i + 1ull;
            pc = QB_CHECK;
        } else if (pc == QB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_quad_byte_xor64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_quad_byte_xor64_loop_target(0xCAFEBABEull));
    return 0;
}
