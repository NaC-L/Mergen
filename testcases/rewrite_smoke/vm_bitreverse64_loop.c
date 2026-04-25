/* PC-state VM running an i64 bit-reverse via a 64-trip shift+or loop.
 *   result = 0;
 *   for i in 0..64:
 *     result = (result << 1) | (state & 1);
 *     state  = state >> 1;
 *   return result;
 * Lift target: vm_bitreverse64_loop_target.
 *
 * Distinct from vm_bitreverse_loop (i32 version, lifter recognizes
 * llvm.bitreverse.i8): exercises a 64-trip explicit fan-in shift+or +
 * shift-right body on full i64 state.  May or may not be recognized as
 * llvm.bitreverse.i64 by the optimizer.
 */
#include <stdio.h>
#include <stdint.h>

enum BrVmPc {
    BR_LOAD       = 0,
    BR_INIT       = 1,
    BR_LOOP_CHECK = 2,
    BR_LOOP_BODY  = 3,
    BR_LOOP_INC   = 4,
    BR_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_bitreverse64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t state  = 0;
    uint64_t result = 0;
    int      pc     = BR_LOAD;

    while (1) {
        if (pc == BR_LOAD) {
            state  = x;
            result = 0ull;
            pc = BR_INIT;
        } else if (pc == BR_INIT) {
            idx = 0;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_LOOP_CHECK) {
            pc = (idx < 64) ? BR_LOOP_BODY : BR_HALT;
        } else if (pc == BR_LOOP_BODY) {
            result = (result << 1) | (state & 1ull);
            state  = state >> 1;
            pc = BR_LOOP_INC;
        } else if (pc == BR_LOOP_INC) {
            idx = idx + 1;
            pc = BR_LOOP_CHECK;
        } else if (pc == BR_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bitreverse64(1)=0x%llx vm_bitreverse64(0xCAFE)=0x%llx\n",
           (unsigned long long)vm_bitreverse64_loop_target(1ull),
           (unsigned long long)vm_bitreverse64_loop_target(0xCAFEull));
    return 0;
}
