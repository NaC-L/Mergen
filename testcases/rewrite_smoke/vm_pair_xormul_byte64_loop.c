/* PC-state VM that processes consecutive byte pairs per iteration:
 *
 *   n = (x & 3) + 1;     // 1..4 pair iterations (up to 4 pairs of bytes)
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b0 = s & 0xFF;
 *     uint64_t b1 = (s >> 8) & 0xFF;
 *     r = r + (b0 ^ b1) * (b0 + b1);
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_pair_xormul_byte64_loop_target.
 *
 * Distinct from:
 *   - All single-byte-per-iter samples (consume 1 byte each iter)
 *   - vm_xormul_byte_idx64_loop (one byte * counter)
 *   - vm_bytesq_sum64_loop      (single-byte squared)
 *
 * Tests TWO byte reads per iteration (b0, b1 from s and s>>8) combined
 * via XOR (b0^b1) and ADD (b0+b1) then MULTIPLY together and ADD-fold.
 * For equal-byte pairs the XOR is 0 so contribution is 0.  Trip count
 * uses `& 3` so loop runs 1..4 times consuming 2 bytes each iter.
 */
#include <stdio.h>
#include <stdint.h>

enum PpVmPc {
    PP_INIT_ALL = 0,
    PP_CHECK    = 1,
    PP_BODY     = 2,
    PP_INC      = 3,
    PP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_pair_xormul_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = PP_INIT_ALL;

    while (1) {
        if (pc == PP_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = PP_CHECK;
        } else if (pc == PP_CHECK) {
            pc = (i < n) ? PP_BODY : PP_HALT;
        } else if (pc == PP_BODY) {
            uint64_t b0 = s & 0xFFull;
            uint64_t b1 = (s >> 8) & 0xFFull;
            r = r + (b0 ^ b1) * (b0 + b1);
            s = s >> 16;
            pc = PP_INC;
        } else if (pc == PP_INC) {
            i = i + 1ull;
            pc = PP_CHECK;
        } else if (pc == PP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pair_xormul_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_pair_xormul_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
