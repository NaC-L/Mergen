/* PC-state VM that XORs each byte shifted left by (i*3) bits into r:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r ^ ((s & 0xFF) << (i * 3));   // dynamic shl by 3*i
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteshl3_xor64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop  (dynamic shl by i directly, 2-bit chunks)
 *   - vm_byterev_window64_loop (constant shl-by-8 packing)
 *   - vm_xormul_byte_idx64_loop (byte * counter, no shift)
 *
 * Tests `shl i64 byte, %i*3` (dynamic shl by a NON-trivial counter
 * expression - mul-then-shl) inside dispatcher loop body.  Each
 * iter's byte lands at a different 3-bit-stride offset, so byte0
 * occupies bits 0-7, byte1 bits 3-10 (overlapping byte0's high), etc.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_INIT_ALL = 0,
    BS_CHECK    = 1,
    BS_BODY     = 2,
    BS_INC      = 3,
    BS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteshl3_xor64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BS_INIT_ALL;

    while (1) {
        if (pc == BS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = BS_CHECK;
        } else if (pc == BS_CHECK) {
            pc = (i < n) ? BS_BODY : BS_HALT;
        } else if (pc == BS_BODY) {
            r = r ^ ((s & 0xFFull) << (i * 3ull));
            s = s >> 8;
            pc = BS_INC;
        } else if (pc == BS_INC) {
            i = i + 1ull;
            pc = BS_CHECK;
        } else if (pc == BS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteshl3_xor64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_byteshl3_xor64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
