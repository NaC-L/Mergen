/* PC-state VM running a two-state cross-feeding mix step with SUB
 * instead of ADD over n iters:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x;
 *   for (i = 0; i < n; i++) {
 *     t = a - b;                    // SUB instead of ADD
 *     a = b * 0x9E3779B97F4A7C15ull;
 *     b = t ^ (t >> 33);
 *   }
 *   return a ^ b;
 *
 * Lift target: vm_pairmix_sub64_loop_target.
 *
 * Distinct from:
 *   - vm_pairmix64_loop (sister: ADD instead of SUB)
 *
 * Two i64 slots (a, b) plus a per-iter temp (t).  Each iteration reads
 * both states into t = a-b, then writes a from b*GR and b from
 * t^(t>>33).  The SUB direction wraps below zero into u64 modular
 * space, exercising different lifter behavior from the ADD pair.
 */
#include <stdio.h>
#include <stdint.h>

enum PmsVmPc {
    PMS_INIT_ALL = 0,
    PMS_CHECK    = 1,
    PMS_BODY     = 2,
    PMS_INC      = 3,
    PMS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_pairmix_sub64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t i  = 0;
    int      pc = PMS_INIT_ALL;

    while (1) {
        if (pc == PMS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            i = 0ull;
            pc = PMS_CHECK;
        } else if (pc == PMS_CHECK) {
            pc = (i < n) ? PMS_BODY : PMS_HALT;
        } else if (pc == PMS_BODY) {
            uint64_t t = a - b;
            a = b * 0x9E3779B97F4A7C15ull;
            b = t ^ (t >> 33);
            pc = PMS_INC;
        } else if (pc == PMS_INC) {
            i = i + 1ull;
            pc = PMS_CHECK;
        } else if (pc == PMS_HALT) {
            return a ^ b;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pairmix_sub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pairmix_sub64_loop_target(0xCAFEBABEull));
    return 0;
}
