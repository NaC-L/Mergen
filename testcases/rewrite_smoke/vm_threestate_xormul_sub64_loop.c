/* PC-state VM running a three-state cross-feeding recurrence with
 * SUBTRACTIVE updates over n iters:
 *
 *   n = (x & 7) + 1;
 *   a = x; b = ~x; c = x * GR;
 *   for (i = 0; i < n; i++) {
 *     t = a ^ b;
 *     a = b;
 *     b = c - 1;                    // SUB instead of ADD
 *     c = t * GR - a;               // SUB instead of ADD
 *   }
 *   return a ^ b ^ c;
 *
 * Lift target: vm_threestate_xormul_sub64_loop_target.
 *
 * Distinct from:
 *   - vm_threestate_xormul64_loop (sister: additive b'+1 and c'+a)
 *
 * Three i64 slots all updated each iteration with sequential reads
 * captured into temp `t`.  Subtractive direction wraps below zero
 * inside the cross-feed.
 */
#include <stdio.h>
#include <stdint.h>

enum TssVmPc {
    TSS_INIT_ALL = 0,
    TSS_CHECK    = 1,
    TSS_BODY     = 2,
    TSS_INC      = 3,
    TSS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_threestate_xormul_sub64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t a  = 0;
    uint64_t b  = 0;
    uint64_t c  = 0;
    uint64_t i  = 0;
    int      pc = TSS_INIT_ALL;

    while (1) {
        if (pc == TSS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            a = x;
            b = ~x;
            c = x * 0x9E3779B97F4A7C15ull;
            i = 0ull;
            pc = TSS_CHECK;
        } else if (pc == TSS_CHECK) {
            pc = (i < n) ? TSS_BODY : TSS_HALT;
        } else if (pc == TSS_BODY) {
            uint64_t t = a ^ b;
            a = b;
            b = c - 1ull;
            c = t * 0x9E3779B97F4A7C15ull - a;
            pc = TSS_INC;
        } else if (pc == TSS_INC) {
            i = i + 1ull;
            pc = TSS_CHECK;
        } else if (pc == TSS_HALT) {
            return a ^ b ^ c;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_threestate_xormul_sub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_threestate_xormul_sub64_loop_target(0xCAFEBABEull));
    return 0;
}
