/* PC-state VM that XOR-folds all 8 bytes of x into a single byte.
 *   result = 0;
 *   for i in 0..8: result ^= (x >> (i*8)) & 0xFF;
 *   return result;     // only low 8 bits non-zero
 * 8-trip fixed loop with byte-walking shift (loop-counter * 8).
 * Lift target: vm_xorbytes64_loop_target.
 *
 * Distinct from vm_djb264_loop (multiplicative byte hash) and
 * vm_morton64_loop (1-bit fan-out spread): exercises an XOR-reduction
 * over byte slices with no multiplication.  Even-byte-count duplicates
 * cancel to zero; result is a single-byte XOR signature.
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_LOAD       = 0,
    XB_INIT       = 1,
    XB_LOOP_CHECK = 2,
    XB_LOOP_BODY  = 3,
    XB_LOOP_INC   = 4,
    XB_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_xorbytes64_loop_target(uint64_t x) {
    int      idx    = 0;
    uint64_t xx     = 0;
    uint64_t result = 0;
    int      pc     = XB_LOAD;

    while (1) {
        if (pc == XB_LOAD) {
            xx     = x;
            result = 0ull;
            pc = XB_INIT;
        } else if (pc == XB_INIT) {
            idx = 0;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_LOOP_CHECK) {
            pc = (idx < 8) ? XB_LOOP_BODY : XB_HALT;
        } else if (pc == XB_LOOP_BODY) {
            result = result ^ ((xx >> (idx * 8)) & 0xFFull);
            pc = XB_LOOP_INC;
        } else if (pc == XB_LOOP_INC) {
            idx = idx + 1;
            pc = XB_LOOP_CHECK;
        } else if (pc == XB_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xorbytes64(0xCAFEBABE)=%llu vm_xorbytes64(0x9E3779B97F4A7C15)=%llu\n",
           (unsigned long long)vm_xorbytes64_loop_target(0xCAFEBABEull),
           (unsigned long long)vm_xorbytes64_loop_target(0x9E3779B97F4A7C15ull));
    return 0;
}
