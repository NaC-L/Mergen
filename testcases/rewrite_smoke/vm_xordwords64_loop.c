/* PC-state VM that XOR-folds both u32 dwords of x into a single u32
 * via a fixed-trip loop:
 *   result = 0;
 *   for i in 0..2: result ^= (x >> (i*32)) & 0xFFFFFFFF;
 *   return result;     // only low 32 bits non-zero
 *
 * 2-trip fixed loop with dword-walking shift (loop-counter * 32).
 * Lift target: vm_xordwords64_loop_target.
 *
 * Distinct from:
 *   - vm_xorwords64_loop  (16-bit stride 4-trip fixed loop)
 *   - vm_xorbytes64_loop  (8-bit stride 8-trip fixed loop)
 *   - vm_dword_xorfold64_loop (variable-trip n=(x&1)+1)
 *
 * Tests an XOR-reduction over u32 slices with a fixed 2-trip loop the
 * lifter is expected to unroll into `(x & 0xFFFFFFFF) ^ (x >> 32)`.
 */
#include <stdio.h>
#include <stdint.h>

enum XdVmPc {
    XD2_LOAD       = 0,
    XD2_INIT       = 1,
    XD2_LOOP_CHECK = 2,
    XD2_LOOP_BODY  = 3,
    XD2_LOOP_INC   = 4,
    XD2_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xordwords64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = XD2_LOAD;

    while (1) {
        if (pc == XD2_LOAD) {
            xx     = x;
            result = 0ull;
            pc = XD2_INIT;
        } else if (pc == XD2_INIT) {
            idx = 0;
            pc = XD2_LOOP_CHECK;
        } else if (pc == XD2_LOOP_CHECK) {
            pc = (idx < 2) ? XD2_LOOP_BODY : XD2_HALT;
        } else if (pc == XD2_LOOP_BODY) {
            result = result ^ ((xx >> (idx * 32)) & 0xFFFFFFFFull);
            pc = XD2_LOOP_INC;
        } else if (pc == XD2_LOOP_INC) {
            idx = idx + 1;
            pc = XD2_LOOP_CHECK;
        } else if (pc == XD2_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xordwords64(0xCAFEBABEDEADBEEF)=%llu\n",
           (unsigned long long)vm_xordwords64_loop_target(0xCAFEBABEDEADBEEFull));
    return 0;
}
