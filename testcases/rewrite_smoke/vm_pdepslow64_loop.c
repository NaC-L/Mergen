/* PC-state VM running an explicit PDEP-style bit-deposit (no intrinsic).
 *   src = x & 0xFFFFFFFF;
 *   mask = (x >> 32) | 1;     // ensure non-zero
 *   result = 0; bit_pos = 0;
 *   for i in 0..64:
 *     if ((mask >> i) & 1):
 *       if ((src >> bit_pos) & 1):
 *         result |= (1 << i);
 *       bit_pos++;
 *   return result;
 * 64-trip fixed loop with two nested bit-tests + conditional bit-deposit.
 * Lift target: vm_pdepslow64_loop_target.
 *
 * Distinct from vm_morton64_loop (fixed every-other-bit spread): the
 * deposit positions are determined by an input-derived MASK, so each
 * call has different scatter pattern.  Bit_pos counter advances only
 * when the mask bit is set - asymmetric loop counter.
 */
#include <stdio.h>
#include <stdint.h>

enum PdVmPc {
    PD_LOAD       = 0,
    PD_INIT       = 1,
    PD_LOOP_CHECK = 2,
    PD_LOOP_BODY  = 3,
    PD_LOOP_INC   = 4,
    PD_HALT       = 5,
};

__declspec(noinline)
uint64_t vm_pdepslow64_loop_target(uint64_t x) {
    int      idx     = 0;
    int      bit_pos = 0;
    uint64_t src     = 0;
    uint64_t mask    = 0;
    uint64_t result  = 0;
    int      pc      = PD_LOAD;

    while (1) {
        if (pc == PD_LOAD) {
            src    = x & 0xFFFFFFFFull;
            mask   = (x >> 32) | 1ull;
            result = 0ull;
            bit_pos = 0;
            pc = PD_INIT;
        } else if (pc == PD_INIT) {
            idx = 0;
            pc = PD_LOOP_CHECK;
        } else if (pc == PD_LOOP_CHECK) {
            pc = (idx < 64) ? PD_LOOP_BODY : PD_HALT;
        } else if (pc == PD_LOOP_BODY) {
            if (((mask >> idx) & 1ull) != 0ull) {
                if (((src >> bit_pos) & 1ull) != 0ull) {
                    result = result | (1ull << idx);
                }
                bit_pos = bit_pos + 1;
            }
            pc = PD_LOOP_INC;
        } else if (pc == PD_LOOP_INC) {
            idx = idx + 1;
            pc = PD_LOOP_CHECK;
        } else if (pc == PD_HALT) {
            return result;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_pdepslow64(0xCAFEBABEDEADBEEF)=%llu vm_pdepslow64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_pdepslow64_loop_target(0xCAFEBABEDEADBEEFull),
           (unsigned long long)vm_pdepslow64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
