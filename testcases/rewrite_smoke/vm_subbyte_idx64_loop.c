/* PC-state VM that SUBTRACTs unsigned-byte * counter from the
 * accumulator over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = r - (s & 0xFF) * (i + 1);   // u8 zext * counter, SUB-folded
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_subbyte_idx64_loop_target.
 *
 * Distinct from:
 *   - vm_uintadd_byte_idx64_loop (same body, ADD-folded)
 *   - vm_xormul_byte_idx64_loop  (same body, XOR-folded)
 *   - vm_andsum_byte_idx64_loop  (byte AND counter, ADD)
 *   - vm_orsum_byte_idx64_loop   (byte OR counter, OR)
 *
 * Completes the binary-op fold matrix for byte * counter accumulator
 * with SUB.  Result wraps below zero into u64 so most non-zero inputs
 * land near 2^64 - small_number.
 */
#include <stdio.h>
#include <stdint.h>

enum SbiVmPc {
    SBI_INIT_ALL = 0,
    SBI_CHECK    = 1,
    SBI_BODY     = 2,
    SBI_INC      = 3,
    SBI_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_subbyte_idx64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SBI_INIT_ALL;

    while (1) {
        if (pc == SBI_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = SBI_CHECK;
        } else if (pc == SBI_CHECK) {
            pc = (i < n) ? SBI_BODY : SBI_HALT;
        } else if (pc == SBI_BODY) {
            r = r - (s & 0xFFull) * (i + 1ull);
            s = s >> 8;
            pc = SBI_INC;
        } else if (pc == SBI_INC) {
            i = i + 1ull;
            pc = SBI_CHECK;
        } else if (pc == SBI_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_subbyte_idx64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_subbyte_idx64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
