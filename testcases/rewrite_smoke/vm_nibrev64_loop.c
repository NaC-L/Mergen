/* PC-state VM applying an i64 NIBBLE-REVERSE (16-way fan-in) for n
 * iterations.  Even-trip = identity, odd-trip = single nibble-reverse.
 *   for k in 0..n:
 *     result = 0
 *     for i in 0..16:
 *       nib = (state >> (i*4)) & 0xF
 *       result |= nib << ((15-i)*4)
 *     state = result
 * Outer trip n = (x & 7) + 1.  Inner is a fixed 16-iteration
 * fan-in/fan-out fully unrolled.
 * Lift target: vm_nibrev64_loop_target.
 *
 * Distinct from vm_bswap64_loop (byte-reverse: 8 bytes shuffled) and
 * vm_bitreverse64_loop (full bit-reverse, folds to llvm.bitreverse.i64).
 * Nibble-reverse is structurally between the two: 16 4-bit chunks
 * permuted, no LLVM intrinsic recognition expected.
 */
#include <stdio.h>
#include <stdint.h>

enum NbVmPc {
    NB_LOAD       = 0,
    NB_INIT       = 1,
    NB_LOOP_CHECK = 2,
    NB_LOOP_BODY  = 3,
    NB_LOOP_INC   = 4,
    NB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_nibrev64_loop_target(uint64_t x) {
    int      idx   = 0;
    int      n     = 0;
    uint64_t state = 0;
    int      pc    = NB_LOAD;

    while (1) {
        if (pc == NB_LOAD) {
            state = x;
            n     = (int)(x & 7ull) + 1;
            pc = NB_INIT;
        } else if (pc == NB_INIT) {
            idx = 0;
            pc = NB_LOOP_CHECK;
        } else if (pc == NB_LOOP_CHECK) {
            pc = (idx < n) ? NB_LOOP_BODY : NB_HALT;
        } else if (pc == NB_LOOP_BODY) {
            uint64_t r = 0ull;
            r |= ((state >>  0) & 0xFull) << 60;
            r |= ((state >>  4) & 0xFull) << 56;
            r |= ((state >>  8) & 0xFull) << 52;
            r |= ((state >> 12) & 0xFull) << 48;
            r |= ((state >> 16) & 0xFull) << 44;
            r |= ((state >> 20) & 0xFull) << 40;
            r |= ((state >> 24) & 0xFull) << 36;
            r |= ((state >> 28) & 0xFull) << 32;
            r |= ((state >> 32) & 0xFull) << 28;
            r |= ((state >> 36) & 0xFull) << 24;
            r |= ((state >> 40) & 0xFull) << 20;
            r |= ((state >> 44) & 0xFull) << 16;
            r |= ((state >> 48) & 0xFull) << 12;
            r |= ((state >> 52) & 0xFull) <<  8;
            r |= ((state >> 56) & 0xFull) <<  4;
            r |= ((state >> 60) & 0xFull) <<  0;
            state = r;
            pc = NB_LOOP_INC;
        } else if (pc == NB_LOOP_INC) {
            idx = idx + 1;
            pc = NB_LOOP_CHECK;
        } else if (pc == NB_HALT) {
            return state;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nibrev64(0xCAFE)=0x%llx vm_nibrev64(0x123456789ABCDEF0)=0x%llx\n",
           (unsigned long long)vm_nibrev64_loop_target(0xCAFEull),
           (unsigned long long)vm_nibrev64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
