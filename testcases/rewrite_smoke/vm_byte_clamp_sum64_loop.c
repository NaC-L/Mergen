/* PC-state VM: clamp byte to [0x40, 0x80] then sum:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t b  = s & 0xFF;
 *     uint64_t lo = (b > 0x40) ? b : 0x40;     // umax(b, 0x40)
 *     uint64_t cl = (lo < 0x80) ? lo : 0x80;   // umin(lo, 0x80)
 *     r = r + cl;
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_clamp_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_byte_max_const_sum64_loop (umax only)
 *   - vm_byte_min_const_sum64_loop (umin only)
 *
 * Tests `llvm.umax.i64` chained with `llvm.umin.i64` (clamp idiom)
 * inside add chain at byte stride.
 */
#include <stdio.h>
#include <stdint.h>

enum BcVmPc {
    BC_INIT_ALL = 0,
    BC_CHECK    = 1,
    BC_BODY     = 2,
    BC_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_byte_clamp_sum64_loop_target(uint64_t x) {
    uint64_t n = 0;
    uint64_t s = 0;
    uint64_t r = 0;
    int      pc = BC_INIT_ALL;

    while (1) {
        if (pc == BC_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            pc = BC_CHECK;
        } else if (pc == BC_CHECK) {
            pc = (n > 0ull) ? BC_BODY : BC_HALT;
        } else if (pc == BC_BODY) {
            uint64_t b  = s & 0xFFull;
            uint64_t lo = (b > 0x40ull) ? b : 0x40ull;
            uint64_t cl = (lo < 0x80ull) ? lo : 0x80ull;
            r = r + cl;
            s = s >> 8;
            n = n - 1ull;
            pc = BC_CHECK;
        } else if (pc == BC_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byte_clamp_sum64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byte_clamp_sum64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
