/* PC-state VM running a 64-bit LFSR with maximal-length feedback taps
 * at positions 0, 1, 3, 4.
 *   state = x | 1;   // ensure non-zero
 *   n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     bit = ((state) ^ (state>>1) ^ (state>>3) ^ (state>>4)) & 1
 *     state = (state >> 1) | (bit << 63);
 *   return state;
 * Lift target: vm_lfsr64_loop_target.
 *
 * Distinct from vm_lfsr_loop (i32 LFSR): exercises full 64-bit state
 * with multi-bit XOR feedback computation and a high-bit OR-merge.
 */
#include <stdio.h>
#include <stdint.h>

enum LfVmPc {
    LF_LOAD       = 0,
    LF_INIT       = 1,
    LF_LOOP_CHECK = 2,
    LF_LOOP_BODY  = 3,
    LF_LOOP_INC   = 4,
    LF_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_lfsr64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = LF_LOAD;

    while (1) {
        if (pc == LF_LOAD) {
            state = x | 1ull;
            n     = (int)(x & 0xFull) + 1;
            pc = LF_INIT;
        } else if (pc == LF_INIT) {
            idx = 0;
            pc = LF_LOOP_CHECK;
        } else if (pc == LF_LOOP_CHECK) {
            pc = (idx < n) ? LF_LOOP_BODY : LF_HALT;
        } else if (pc == LF_LOOP_BODY) {
            uint64_t bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1ull;
            state = (state >> 1) | (bit << 63);
            pc = LF_LOOP_INC;
        } else if (pc == LF_LOOP_INC) {
            idx = idx + 1;
            pc = LF_LOOP_CHECK;
        } else if (pc == LF_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_lfsr64(0xCAFE)=0x%llx vm_lfsr64(0xFF)=0x%llx\n",
           (unsigned long long)vm_lfsr64_loop_target(0xCAFEull),
           (unsigned long long)vm_lfsr64_loop_target(0xFFull));
    return 0;
}
