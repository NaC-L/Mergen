/* PC-state VM that builds r by shifting it left by (i+1) bits then
 * adding the next byte over n = (x & 7) + 1 iterations:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << (i + 1)) + (s & 0xFF);   // shl ACCUMULATOR by counter
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_dynshl_accum_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_dynshl_pack64_loop     (shl BYTE by counter, fixed-width chunk)
 *   - vm_byteshl3_xor64_loop    (shl byte by i*3, XOR-folded)
 *   - vm_byteshl_data64_loop    (data-dependent shl on accumulator)
 *
 * Tests `shl i64 %r, %(i+1)` (shift ACCUMULATOR by phi-tracked counter
 * rather than shifting the byte) plus byte ADD.  Each iter the
 * accumulator grows by (i+1) bits; cumulative shift is 1+2+...+n.
 */
#include <stdio.h>
#include <stdint.h>

enum DaVmPc {
    DA_INIT_ALL = 0,
    DA_CHECK    = 1,
    DA_BODY     = 2,
    DA_INC      = 3,
    DA_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_dynshl_accum_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = DA_INIT_ALL;

    while (1) {
        if (pc == DA_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = DA_CHECK;
        } else if (pc == DA_CHECK) {
            pc = (i < n) ? DA_BODY : DA_HALT;
        } else if (pc == DA_BODY) {
            r = (r << (i + 1ull)) + (s & 0xFFull);
            s = s >> 8;
            pc = DA_INC;
        } else if (pc == DA_INC) {
            i = i + 1ull;
            pc = DA_CHECK;
        } else if (pc == DA_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_dynshl_accum_byte64(0xFFFFFFFFFFFFFFFF)=%llu\n",
           (unsigned long long)vm_dynshl_accum_byte64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
