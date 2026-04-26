/* PC-state VM running ZigZag encoding chained over a stepped state
 * with SUBTRACTIVE step:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
 *     r = r + enc;
 *     s = s - 0x9E3779B97F4A7C15;     // SUB instead of ADD
 *   }
 *   return r;
 *
 * Lift target: vm_zigzag_substep64_loop_target.
 *
 * Distinct from:
 *   - vm_zigzag_step64_loop (sister: ADD instead of SUB)
 *
 * ZigZag encoding chained with golden-ratio additive step replaced by
 * subtractive step.  ashr-i64-by-63 sign broadcast still produces the
 * same encoding shape per iter; the s-update direction flips.
 */
#include <stdio.h>
#include <stdint.h>

enum ZzsVmPc {
    ZZS_INIT_ALL = 0,
    ZZS_CHECK    = 1,
    ZZS_BODY     = 2,
    ZZS_INC      = 3,
    ZZS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_zigzag_substep64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = ZZS_INIT_ALL;

    while (1) {
        if (pc == ZZS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = ZZS_CHECK;
        } else if (pc == ZZS_CHECK) {
            pc = (i < n) ? ZZS_BODY : ZZS_HALT;
        } else if (pc == ZZS_BODY) {
            uint64_t enc = (s << 1) ^ (uint64_t)((int64_t)s >> 63);
            r = r + enc;
            s = s - 0x9E3779B97F4A7C15ull;
            pc = ZZS_INC;
        } else if (pc == ZZS_INC) {
            i = i + 1ull;
            pc = ZZS_CHECK;
        } else if (pc == ZZS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_zigzag_substep64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_zigzag_substep64_loop_target(0xCAFEBABEull));
    return 0;
}
