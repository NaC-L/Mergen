/* PC-state VM running Marsaglia's xorshift64 PRNG.
 *   state = x | 1;
 *   for i in 0..n: { state ^= state << 13; state ^= state >> 7; state ^= state << 17; }
 *   return state;
 * Variable trip n = (x & 7) + 1 (1..8).  Returns full uint64_t.
 * Lift target: vm_xorshift64_loop_target.
 *
 * Distinct from vm_lfsr64_loop (single-bit feedback) and vm_pcg64_loop
 * (LCG step + xor-shift output): exercises three sequential shift+xor
 * compound operations per loop iteration on full i64 state, with mixed
 * left-shift and right-shift directions.
 */
#include <stdio.h>
#include <stdint.h>

enum XsVmPc {
    XS_LOAD       = 0,
    XS_INIT       = 1,
    XS_LOOP_CHECK = 2,
    XS_LOOP_BODY  = 3,
    XS_LOOP_INC   = 4,
    XS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorshift64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = XS_LOAD;

    while (1) {
        if (pc == XS_LOAD) {
            state = x | 1ull;
            n     = (int)(x & 7ull) + 1;
            pc = XS_INIT;
        } else if (pc == XS_INIT) {
            idx = 0;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_LOOP_CHECK) {
            pc = (idx < n) ? XS_LOOP_BODY : XS_HALT;
        } else if (pc == XS_LOOP_BODY) {
            state = state ^ (state << 13);
            state = state ^ (state >> 7);
            state = state ^ (state << 17);
            pc = XS_LOOP_INC;
        } else if (pc == XS_LOOP_INC) {
            idx = idx + 1;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorshift64(0xCAFE)=%llu vm_xorshift64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xorshift64_loop_target(0xCAFEull),
           (unsigned long long)vm_xorshift64_loop_target(0xCAFEBABEull));
    return 0;
}
