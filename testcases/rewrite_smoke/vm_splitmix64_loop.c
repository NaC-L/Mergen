/* PC-state VM running n iterations of the SplitMix64 PRNG.
 *   state = x;  z = 0;
 *   for i in 0..n:
 *     state += 0x9E3779B97F4A7C15
 *     z = state
 *     z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
 *     z = (z ^ (z >> 27)) * 0x94D049BB133111EB
 *     z = z ^ (z >> 31)
 *   return z;
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_splitmix64_loop_target.
 *
 * Distinct from vm_xorshift64_loop / vm_xs64star_loop / vm_pcg64_loop /
 * vm_fmix64_loop: SplitMix64 uses TWO multiplications (both by distinct
 * 64-bit primes) interleaved with three xor-with-shift steps inside a
 * loop body that also advances a 64-bit Weyl-style counter.
 */
#include <stdio.h>
#include <stdint.h>

enum SmVmPc {
    SMV_LOAD       = 0,
    SMV_INIT       = 1,
    SMV_LOOP_CHECK = 2,
    SMV_LOOP_BODY  = 3,
    SMV_LOOP_INC   = 4,
    SMV_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_splitmix64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    uint64_t z     = 0;
    int      pc    = SMV_LOAD;

    while (1) {
        if (pc == SMV_LOAD) {
            state = x;
            z     = 0ull;
            n     = (int)(x & 7ull) + 1;
            pc = SMV_INIT;
        } else if (pc == SMV_INIT) {
            idx = 0;
            pc = SMV_LOOP_CHECK;
        } else if (pc == SMV_LOOP_CHECK) {
            pc = (idx < n) ? SMV_LOOP_BODY : SMV_HALT;
        } else if (pc == SMV_LOOP_BODY) {
            state = state + 0x9E3779B97F4A7C15ull;
            z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
            z = z ^ (z >> 31);
            pc = SMV_LOOP_INC;
        } else if (pc == SMV_LOOP_INC) {
            idx = idx + 1;
            pc = SMV_LOOP_CHECK;
        } else if (pc == SMV_HALT) {
            return z;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_splitmix64(0xCAFE)=%llu vm_splitmix64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_splitmix64_loop_target(0xCAFEull),
           (unsigned long long)vm_splitmix64_loop_target(0xDEADBEEFull));
    return 0;
}
