/* PC-state VM running the MurmurHash3 fmix64 final-mixer in a
 * variable-trip loop.  Per iteration:
 *   state ^= state >> 33;
 *   state *= 0xFF51AFD7ED558CCD;
 *   state ^= state >> 33;
 *   state *= 0xC4CEB9FE1A85EC53;
 *   state ^= state >> 33;
 * Variable trip n = (x & 7) + 1.  Returns full uint64_t.
 * Lift target: vm_fmix64_loop_target.
 *
 * Distinct from vm_xorshift64_loop (3-step shift+xor without mul) and
 * vm_pcg64_loop (single mul + add): exercises an alternating xor-shift
 * and multiply-by-large-constant chain (5 ops per iteration) on full i64.
 */
#include <stdio.h>
#include <stdint.h>

enum FmVmPc {
    FM_LOAD       = 0,
    FM_INIT       = 1,
    FM_LOOP_CHECK = 2,
    FM_LOOP_BODY  = 3,
    FM_LOOP_INC   = 4,
    FM_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_fmix64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = FM_LOAD;

    while (1) {
        if (pc == FM_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = FM_INIT;
        } else if (pc == FM_INIT) {
            idx = 0;
            pc = FM_LOOP_CHECK;
        } else if (pc == FM_LOOP_CHECK) {
            pc = (idx < n) ? FM_LOOP_BODY : FM_HALT;
        } else if (pc == FM_LOOP_BODY) {
            state = state ^ (state >> 33);
            state = state * 0xFF51AFD7ED558CCDull;
            state = state ^ (state >> 33);
            state = state * 0xC4CEB9FE1A85EC53ull;
            state = state ^ (state >> 33);
            pc = FM_LOOP_INC;
        } else if (pc == FM_LOOP_INC) {
            idx = idx + 1;
            pc = FM_LOOP_CHECK;
        } else if (pc == FM_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_fmix64(0xCAFE)=%llu vm_fmix64(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_fmix64_loop_target(0xCAFEull),
           (unsigned long long)vm_fmix64_loop_target(0xDEADBEEFull));
    return 0;
}
