/* PC-state VM that computes the sum of SQUARED per-byte popcounts.
 *   total = 0;
 *   for i in 0..8:
 *     byte = (x >> (i*8)) & 0xFF;
 *     pop = popcount8(byte);          // 0..8 via Brian Kernighan
 *     total += pop * pop;
 *   return total;
 * Outer 8-trip fixed loop containing an INNER variable-trip popcount.
 * Lift target: vm_popsq64_loop_target.
 *
 * Distinct from vm_popcount64_loop (single popcount over whole i64) and
 * vm_byteparity64_loop (1-bit reduction per byte): per-byte popcount
 * (full 0..8 count) followed by squaring then summing.  Inner loop is
 * data-dependent, outer is fixed - tests outer-fixed/inner-variable
 * nested-loop shape.
 */
#include <stdio.h>
#include <stdint.h>

enum PsVmPc {
    PS_LOAD       = 0,
    PS_OUTER_INIT = 1,
    PS_OUTER_CHK  = 2,
    PS_INNER_INIT = 3,
    PS_INNER_CHK  = 4,
    PS_INNER_BODY = 5,
    PS_OUTER_BODY = 6,
    PS_OUTER_INC  = 7,
    PS_HALT       = 8,
};

__declspec(noinline)
int vm_popsq64_loop_target(uint64_t x) {
    int      i     = 0;
    uint64_t xx    = 0;
    uint64_t b     = 0;
    int      pop   = 0;
    int      total = 0;
    int      pc    = PS_LOAD;

    while (1) {
        if (pc == PS_LOAD) {
            xx    = x;
            total = 0;
            pc = PS_OUTER_INIT;
        } else if (pc == PS_OUTER_INIT) {
            i = 0;
            pc = PS_OUTER_CHK;
        } else if (pc == PS_OUTER_CHK) {
            pc = (i < 8) ? PS_INNER_INIT : PS_HALT;
        } else if (pc == PS_INNER_INIT) {
            b   = (xx >> (i * 8)) & 0xFFull;
            pop = 0;
            pc = PS_INNER_CHK;
        } else if (pc == PS_INNER_CHK) {
            pc = (b != 0ull) ? PS_INNER_BODY : PS_OUTER_BODY;
        } else if (pc == PS_INNER_BODY) {
            b = b & (b - 1ull);
            pop = pop + 1;
            pc = PS_INNER_CHK;
        } else if (pc == PS_OUTER_BODY) {
            total = total + pop * pop;
            pc = PS_OUTER_INC;
        } else if (pc == PS_OUTER_INC) {
            i = i + 1;
            pc = PS_OUTER_CHK;
        } else if (pc == PS_HALT) {
            return total;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popsq64(0xCAFEBABEDEADBEEF)=%d vm_popsq64(0x0102030405060708)=%d\n",
           vm_popsq64_loop_target(0xCAFEBABEDEADBEEFull),
           vm_popsq64_loop_target(0x0102030405060708ull));
    return 0;
}
