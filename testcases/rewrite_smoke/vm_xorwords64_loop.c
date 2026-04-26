/* PC-state VM that XOR-folds all 4 u16 words of x into a single u16
 * via a fixed-trip loop:
 *   result = 0;
 *   for i in 0..4: result ^= (x >> (i*16)) & 0xFFFF;
 *   return result;     // only low 16 bits non-zero
 *
 * 4-trip fixed loop with word-walking shift (loop-counter * 16).
 * Lift target: vm_xorwords64_loop_target.
 *
 * Distinct from:
 *   - vm_xorbytes64_loop (byte-stride 8-trip fixed loop)
 *   - vm_word_xorfold64_loop (variable-trip n=(x&3)+1)
 *
 * Tests an XOR-reduction over u16 slices with a fixed-bound loop the
 * lifter is expected to fully unroll into a chain of shifts + XORs.
 */
#include <stdio.h>
#include <stdint.h>

enum XwVmPc {
    XW2_LOAD       = 0,
    XW2_INIT       = 1,
    XW2_LOOP_CHECK = 2,
    XW2_LOOP_BODY  = 3,
    XW2_LOOP_INC   = 4,
    XW2_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorwords64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = XW2_LOAD;

    while (1) {
        if (pc == XW2_LOAD) {
            xx     = x;
            result = 0ull;
            pc = XW2_INIT;
        } else if (pc == XW2_INIT) {
            idx = 0;
            pc = XW2_LOOP_CHECK;
        } else if (pc == XW2_LOOP_CHECK) {
            pc = (idx < 4) ? XW2_LOOP_BODY : XW2_HALT;
        } else if (pc == XW2_LOOP_BODY) {
            result = result ^ ((xx >> (idx * 16)) & 0xFFFFull);
            pc = XW2_LOOP_INC;
        } else if (pc == XW2_LOOP_INC) {
            idx = idx + 1;
            pc = XW2_LOOP_CHECK;
        } else if (pc == XW2_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorwords64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xorwords64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
