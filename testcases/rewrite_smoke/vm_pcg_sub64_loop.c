/* PC-state VM running a PCG-style i64 RNG with SUBTRACTIVE LCG
 * increment:
 *
 *   state = x;
 *   for i in 0..n: state = state * 0x5851F42D4C957F2D - 1;   // SUB instead of ADD
 *   return state ^ (state >> 33);
 *
 * Variable trip n = (x & 7) + 1 (1..8).  Returns full uint64_t.
 *
 * Lift target: vm_pcg_sub64_loop_target.
 *
 * Distinct from:
 *   - vm_pcg64_loop (sister: state = state * MUL + 1 instead of - 1)
 *
 * Same i64 LCG-with-xorshift-output shape but the LCG increment is
 * subtractive.  Tests u64 underflow inside the LCG state-update with
 * a final lshr33 xor mix.
 */
#include <stdio.h>
#include <stdint.h>

enum PgsVmPc {
    PGS_LOAD       = 0,
    PGS_INIT       = 1,
    PGS_LOOP_CHECK = 2,
    PGS_LOOP_BODY  = 3,
    PGS_LOOP_INC   = 4,
    PGS_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pcg_sub64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = PGS_LOAD;

    while (1) {
        if (pc == PGS_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = PGS_INIT;
        } else if (pc == PGS_INIT) {
            idx = 0;
            pc = PGS_LOOP_CHECK;
        } else if (pc == PGS_LOOP_CHECK) {
            pc = (idx < n) ? PGS_LOOP_BODY : PGS_HALT;
        } else if (pc == PGS_LOOP_BODY) {
            state = state * 0x5851F42D4C957F2Dull - 1ull;
            pc = PGS_LOOP_INC;
        } else if (pc == PGS_LOOP_INC) {
            idx = idx + 1;
            pc = PGS_LOOP_CHECK;
        } else if (pc == PGS_HALT) {
            return state ^ (state >> 33);
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pcg_sub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pcg_sub64_loop_target(0xCAFEBABEull));
    return 0;
}
