/* PC-state VM running a 64-bit Galois-form LFSR (left-shifting) with
 * feedback taps at high positions:
 *   state = x | (1ull << 63);   // ensure non-zero high bit
 *   n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     bit = ((state>>63) ^ (state>>62) ^ (state>>60) ^ (state>>59)) & 1
 *     state = (state << 1) | bit;
 *   return state;
 * Lift target: vm_lfsr64_galois_loop_target.
 *
 * Distinct from:
 *   - vm_lfsr64_loop (Fibonacci-form: shift right, feed at MSB)
 *
 * Galois pair to vm_lfsr64_loop: same maximal-length tap polynomial but
 * shifting left and feeding at LSB instead of right + MSB.  Tests
 * symmetric direction at u64 width.
 */
#include <stdio.h>
#include <stdint.h>

enum LfgVmPc {
    LFG_LOAD       = 0,
    LFG_INIT       = 1,
    LFG_LOOP_CHECK = 2,
    LFG_LOOP_BODY  = 3,
    LFG_LOOP_INC   = 4,
    LFG_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_lfsr64_galois_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = LFG_LOAD;

    while (1) {
        if (pc == LFG_LOAD) {
            state = x | (1ull << 63);
            n     = (int)(x & 0xFull) + 1;
            pc = LFG_INIT;
        } else if (pc == LFG_INIT) {
            idx = 0;
            pc = LFG_LOOP_CHECK;
        } else if (pc == LFG_LOOP_CHECK) {
            pc = (idx < n) ? LFG_LOOP_BODY : LFG_HALT;
        } else if (pc == LFG_LOOP_BODY) {
            uint64_t bit = ((state >> 63) ^ (state >> 62) ^ (state >> 60) ^ (state >> 59)) & 1ull;
            state = (state << 1) | bit;
            pc = LFG_LOOP_INC;
        } else if (pc == LFG_LOOP_INC) {
            idx = idx + 1;
            pc = LFG_LOOP_CHECK;
        } else if (pc == LFG_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lfsr64_galois(0x1)=%llu\n",
           (unsigned long long)vm_lfsr64_galois_loop_target(0x1ull));
    return 0;
}
