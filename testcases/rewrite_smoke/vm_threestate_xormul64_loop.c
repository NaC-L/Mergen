/* PC-state VM running a three-state cross-feeding recurrence over n iters:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x; c = x * GR;
 *   for (i = 0; i < n; i++) {
 *     t = a ^ b;
 *     a = b;
 *     b = c + 1;
 *     c = t * GR + a;     // GR = 0x9E3779B97F4A7C15
 *   }
 *   return a ^ b ^ c;
 *
 * Lift target: vm_threestate_xormul64_loop_target.
 *
 * Distinct from:
 *   - vm_tribonacci64_loop  (additive a,b,c -> b,c,a+b+c)
 *   - vm_pairmix64_loop     (two-state cross-feed with temp barrier)
 *   - vm_xs64star / vm_splitmix64 (single-state PRNGs)
 *
 * Three i64 slots all updated each iteration with sequential reads
 * captured into temp `t` before any writeback (TEA-bug workaround).
 * Body mixes xor (t), increment (b'), multiply-by-GR + add (c').
 * Returns combined a^b^c at the end.
 */
#include <stdio.h>
#include <stdint.h>

enum TsVmPc {
    TS_INIT_ALL = 0,
    TS_CHECK    = 1,
    TS_BODY     = 2,
    TS_INC      = 3,
    TS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_threestate_xormul64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t c  = 0;
    uint64_t i  = 0;
    int      pc = TS_INIT_ALL;

    while (1) {
        if (pc == TS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            c = x * 0x9E3779B97F4A7C15ull;
            i = 0ull;
            pc = TS_CHECK;
        } else if (pc == TS_CHECK) {
            pc = (i < n) ? TS_BODY : TS_HALT;
        } else if (pc == TS_BODY) {
            uint64_t t = a ^ b;
            a = b;
            b = c + 1ull;
            c = t * 0x9E3779B97F4A7C15ull + a;
            pc = TS_INC;
        } else if (pc == TS_INC) {
            i = i + 1ull;
            pc = TS_CHECK;
        } else if (pc == TS_HALT) {
            return a ^ b ^ c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_threestate_xormul64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_threestate_xormul64_loop_target(0xCAFEBABEull));
    return 0;
}
