/* PC-state VM with a per-iteration rotation-direction choice driven by
 * the input bits.
 *   s = x; n = (x & 0xF) + 1;
 *   for i in 0..n:
 *     bit = (x >> i) & 1
 *     s = bit ? rotl(s, 7) : rotr(s, 11)
 *   return s;
 * Lift target: vm_rotchoice64_loop_target.
 *
 * Distinct from vm_rotl64_loop (single-direction rotation) and
 * vm_treepath64_loop (mul/+1 vs *2 binary tree): the body chooses
 * BETWEEN two rotation primitives with different amounts per iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum RcVmPc {
    RC_LOAD       = 0,
    RC_INIT       = 1,
    RC_LOOP_CHECK = 2,
    RC_LOOP_BODY  = 3,
    RC_LOOP_INC   = 4,
    RC_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_rotchoice64_loop_target(uint64_t x) {
    int      idx = 0;
    int      n   = 0;
    uint64_t xx  = 0;
    uint64_t s   = 0;
    int      pc  = RC_LOAD;

    while (1) {
        if (pc == RC_LOAD) {
            xx = x;
            s  = x;
            n  = (int)(x & 0xFull) + 1;
            pc = RC_INIT;
        } else if (pc == RC_INIT) {
            idx = 0;
            pc = RC_LOOP_CHECK;
        } else if (pc == RC_LOOP_CHECK) {
            pc = (idx < n) ? RC_LOOP_BODY : RC_HALT;
        } else if (pc == RC_LOOP_BODY) {
            uint64_t bit = (xx >> idx) & 1ull;
            if (bit) {
                s = (s << 7) | (s >> 57);    /* rotl 7 */
            } else {
                s = (s >> 11) | (s << 53);   /* rotr 11 */
            }
            pc = RC_LOOP_INC;
        } else if (pc == RC_LOOP_INC) {
            idx = idx + 1;
            pc = RC_LOOP_CHECK;
        } else if (pc == RC_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_rotchoice64(0xCAFE)=%llu vm_rotchoice64(0xAA)=%llu\n",
           (unsigned long long)vm_rotchoice64_loop_target(0xCAFEull),
           (unsigned long long)vm_rotchoice64_loop_target(0xAAull));
    return 0;
}
