/* PC-state VM running Marsaglia xorshift64* (xorshift body 12/25/27 +
 * final multiply by 0x2545F4914F6CDD1D).
 *   state = x | 1;
 *   for i in 0..n: { state ^= state >> 12; state ^= state << 25; state ^= state >> 27; }
 *   return state * 0x2545F4914F6CDD1D;
 * Variable trip n = (x & 7) + 1.
 * Lift target: vm_xs64star_loop_target.
 *
 * Distinct from vm_xorshift64_loop (13/7/17 shifts, no final mul) and
 * vm_pcg64_loop (mul-then-xor): different shift triple plus a final
 * post-loop multiplication by a 64-bit constant for output mixing.
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
uint64_t vm_xs64star_loop_target(uint64_t x) {
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
            state = state ^ (state >> 12);
            state = state ^ (state << 25);
            state = state ^ (state >> 27);
            pc = XS_LOOP_INC;
        } else if (pc == XS_LOOP_INC) {
            idx = idx + 1;
            pc = XS_LOOP_CHECK;
        } else if (pc == XS_HALT) {
            return state * 0x2545F4914F6CDD1Dull;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xs64star(0xCAFE)=%llu vm_xs64star(0xDEADBEEF)=%llu\n",
           (unsigned long long)vm_xs64star_loop_target(0xCAFEull),
           (unsigned long long)vm_xs64star_loop_target(0xDEADBEEFull));
    return 0;
}
