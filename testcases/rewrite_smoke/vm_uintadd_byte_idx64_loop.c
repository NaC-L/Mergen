/* PC-state VM that ADDs unsigned-byte * counter into the accumulator
 * over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r + (s & 0xFF) * (i + 1);   // u8 zext * counter, ADD-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_uintadd_byte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesmul_idx64_loop      (signed sext byte * counter, ADD-folded)
 *   - vm_xormul_byte_idx64_loop   (unsigned zext byte * counter, XOR-folded)
 *   - vm_signedxor_byte_idx64_loop (signed sext byte * counter, XOR-folded)
 *
 * Fills the zext+ADD cell - completes the per-byte * counter matrix
 * across all four (zext/sext) x (ADD/XOR) cells.  All-0xFF input
 * accumulates 0xFF * (1+2+...+8) = 0xFF * 36 = 9180 (positive, no
 * sign-extension into upper bits).
 */
#include <stdio.h>
#include <stdint.h>

enum UbVmPc {
    UB_INIT_ALL = 0,
    UB_CHECK    = 1,
    UB_BODY     = 2,
    UB_INC      = 3,
    UB_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_uintadd_byte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = UB_INIT_ALL;

    while (1) {
        if (pc == UB_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = UB_CHECK;
        } else if (pc == UB_CHECK) {
            pc = (i < n) ? UB_BODY : UB_HALT;
        } else if (pc == UB_BODY) {
            r = r + (s & 0xFFull) * (i + 1ull);
            s = s >> 8;
            pc = UB_INC;
        } else if (pc == UB_INC) {
            i = i + 1ull;
            pc = UB_CHECK;
        } else if (pc == UB_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_uintadd_byte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_uintadd_byte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
