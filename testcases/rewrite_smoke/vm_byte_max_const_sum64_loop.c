/* PC-state VM: r += umax(byte, 0x40) per iter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint64_t b = s & 0xFF;
 *     uint64_t m = (b > 0x40) ? b : 0x40;     // umax against constant
 *     r = r + m;
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_byte_max_const_sum64_loop_target.
 *
 * Distinct from:
 *   - vm_bytemax64_loop (cmp-driven max reduction, no add)
 *   - vm_byte_lt_thresh_count64_loop (cmp counter, no max)
 *
 * Tests `llvm.umax.i64` fold (cmp-and-select against constant) inside
 * add chain at byte stride.  Lifter is expected to fold the
 * `(b > C) ? b : C` idiom to llvm.umax.i64 per documented unsigned
 * fold behavior.
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
uint64_t vm_byte_max_const_sum64_loop_target(uint64_t x) {
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
            uint64_t b = s & 0xFFull;
            uint64_t m = (b > 0x40ull) ? b : 0x40ull;
            r = r + m;
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
    printf("vm_byte_max_const_sum64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byte_max_const_sum64_loop_target(0xCAFEBABEull));
    return 0;
}
