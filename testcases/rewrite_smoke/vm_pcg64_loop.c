/* PC-state VM running a PCG-style i64 RNG.
 *   state = x;
 *   for i in 0..n: state = state * 0x5851F42D4C957F2D + 1;
 *   return state ^ (state >> 33);
 * Variable trip n = (x & 7) + 1 (1..8).  Returns full uint64_t.
 * Lift target: vm_pcg64_loop_target.
 *
 * Distinct from vm_pcg_loop (i32 PCG) and vm_lcg_loop: exercises a
 * 64-bit LCG step (full i64 mul + add) followed by an XOR-shift mix
 * for output extraction.
 */
#include <stdio.h>
#include <stdint.h>

enum PgVmPc {
    PG_LOAD       = 0,
    PG_INIT       = 1,
    PG_LOOP_CHECK = 2,
    PG_LOOP_BODY  = 3,
    PG_LOOP_INC   = 4,
    PG_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pcg64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = PG_LOAD;

    while (1) {
        if (pc == PG_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = PG_INIT;
        } else if (pc == PG_INIT) {
            idx = 0;
            pc = PG_LOOP_CHECK;
        } else if (pc == PG_LOOP_CHECK) {
            pc = (idx < n) ? PG_LOOP_BODY : PG_HALT;
        } else if (pc == PG_LOOP_BODY) {
            state = state * 0x5851F42D4C957F2Dull + 1ull;
            pc = PG_LOOP_INC;
        } else if (pc == PG_LOOP_INC) {
            idx = idx + 1;
            pc = PG_LOOP_CHECK;
        } else if (pc == PG_HALT) {
            return state ^ (state >> 33);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pcg64(0xCAFE)=%llu vm_pcg64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pcg64_loop_target(0xCAFEull),
           (unsigned long long)vm_pcg64_loop_target(0xCAFEBABEull));
    return 0;
}
