/* PC-state VM that computes the running product of u16 words:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 1;
 *   for (i = 0; i < n; i++) {
 *     r = r * (s & 0xFFFF);    // u16 multiplicative chain (mod 2^64)
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_wordprod64_loop_target.
 *
 * Distinct from:
 *   - vm_byteprod64_loop  (8-bit stride)
 *   - vm_word_xormul64_loop (per-word self-multiply XOR-folded, not chained)
 *
 * Tests `mul i64 r, word` chained across iterations at u16 stride.
 * Any zero word collapses the product to 0 for the rest of the loop.
 */
#include <stdio.h>
#include <stdint.h>

enum WpVmPc {
    WP_INIT_ALL = 0,
    WP_CHECK    = 1,
    WP_BODY     = 2,
    WP_INC      = 3,
    WP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_wordprod64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = WP_INIT_ALL;

    while (1) {
        if (pc == WP_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 1ull;
            i = 0ull;
            pc = WP_CHECK;
        } else if (pc == WP_CHECK) {
            pc = (i < n) ? WP_BODY : WP_HALT;
        } else if (pc == WP_BODY) {
            r = r * (s & 0xFFFFull);
            s = s >> 16;
            pc = WP_INC;
        } else if (pc == WP_INC) {
            i = i + 1ull;
            pc = WP_CHECK;
        } else if (pc == WP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordprod64(0x0002000300050007)=%llu\n",
           (unsigned long long)vm_wordprod64_loop_target(0x0002000300050007ull));
    return 0;
}
