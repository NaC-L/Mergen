/* PC-state VM that XORs scaled bytes into the accumulator across
 * n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) * (i + 1));   // unsigned byte * counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormul_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop  (signed-byte sext + ADD accumulator)
 *   - vm_byteparity64_loop    (1-bit parity, no scaling)
 *   - vm_xorbytes64_loop      (XOR of bytes, no scaling)
 *
 * Tests unsigned byte (zext-i8) multiplied by dynamic counter (i+1)
 * folded into the accumulator via XOR rather than ADD.  The output
 * stays small for inputs whose bytes XOR to 0 after scaling (e.g.
 * all-0xFF cancels by symmetry of *1 ^ *2 ^ ... ^ *8 with same byte).
 */
#include <stdio.h>
#include <stdint.h>

enum XbVmPc {
    XB_INIT_ALL = 0,
    XB_CHECK    = 1,
    XB_BODY     = 2,
    XB_INC      = 3,
    XB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormul_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XB_INIT_ALL;

    while (1) {
        if (pc == XB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XB_CHECK;
        } else if (pc == XB_CHECK) {
            pc = (i < n) ? XB_BODY : XB_HALT;
        } else if (pc == XB_BODY) {
            r = r ^ ((s & 0xFFull) * (i + 1ull));
            s = s >> 8;
            pc = XB_INC;
        } else if (pc == XB_INC) {
            i = i + 1ull;
            pc = XB_CHECK;
        } else if (pc == XB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormul_byte_idx64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormul_byte_idx64_loop_target(0xCAFEBABEull));
    return 0;
}
