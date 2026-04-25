/* PC-state VM running an i64 Morton (Z-order) bit-spread of low 32 bits
 * to 64 bits.  For each of 32 input bits, place bit i of input at bit
 * position 2*i of output (leaving 2*i+1 as zero).  32-trip fixed loop.
 *   result = 0;
 *   for i in 0..32:
 *     bit = (state >> i) & 1
 *     result |= bit << (2*i)
 *   return result;
 * Lift target: vm_morton64_loop_target.
 *
 * Distinct from vm_bswap64_loop (whole-byte permute) and
 * vm_nibrev64_loop (whole-nibble permute): exercises a 1-bit-stride
 * fan-out where each bit is placed at a different even position.  The
 * lifter likely cannot recognize this as any LLVM intrinsic.
 */
#include <stdio.h>
#include <stdint.h>

enum MoVmPc {
    MO_LOAD       = 0,
    MO_INIT       = 1,
    MO_LOOP_CHECK = 2,
    MO_LOOP_BODY  = 3,
    MO_LOOP_INC   = 4,
    MO_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_morton64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = MO_LOAD;

    while (1) {
        if (pc == MO_LOAD) {
            state  = x & 0xFFFFFFFFull;
            result = 0ull;
            pc = MO_INIT;
        } else if (pc == MO_INIT) {
            idx = 0;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_LOOP_CHECK) {
            pc = (idx < 32) ? MO_LOOP_BODY : MO_HALT;
        } else if (pc == MO_LOOP_BODY) {
            uint64_t bit = (state >> idx) & 1ull;
            result = result | (bit << (2 * idx));
            pc = MO_LOOP_INC;
        } else if (pc == MO_LOOP_INC) {
            idx = idx + 1;
            pc = MO_LOOP_CHECK;
        } else if (pc == MO_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_morton64(0xFFFFFFFF)=%llu vm_morton64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_morton64_loop_target(0xFFFFFFFFull),
           (unsigned long long)vm_morton64_loop_target(0xCAFEBABEull));
    return 0;
}
