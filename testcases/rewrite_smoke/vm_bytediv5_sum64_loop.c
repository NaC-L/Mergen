/* PC-state VM that sums byte / 5 over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + ((s & 0xFF) / 5);   // udiv by 5
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_bytediv5_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_adler32_64_loop          (urem by 65521 - prime modular)
 *   - vm_trailzeros_factorial64_loop (udiv by 5 on a single state, log_5)
 *   - vm_uintadd_byte_idx64_loop  (byte * counter - mul not div)
 *
 * Tests `udiv i64 byte, 5` per iteration on a byte stream.  Compiler
 * may lower /5 to magic-number multiply but the lifter typically
 * preserves it as raw udiv (per documented Adler urem behavior).
 * All-0xFF accumulates 8 * (255/5) = 8 * 51 = 408.
 */
#include <stdio.h>
#include <stdint.h>

enum BdVmPc {
    BD_INIT_ALL = 0,
    BD_CHECK    = 1,
    BD_BODY     = 2,
    BD_INC      = 3,
    BD_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bytediv5_sum64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BD_INIT_ALL;

    while (1) {
        if (pc == BD_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BD_CHECK;
        } else if (pc == BD_CHECK) {
            pc = (i < n) ? BD_BODY : BD_HALT;
        } else if (pc == BD_BODY) {
            r = r + ((s & 0xFFull) / 5ull);
            s = s >> 8;
            pc = BD_INC;
        } else if (pc == BD_INC) {
            i = i + 1ull;
            pc = BD_CHECK;
        } else if (pc == BD_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytediv5_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_bytediv5_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
