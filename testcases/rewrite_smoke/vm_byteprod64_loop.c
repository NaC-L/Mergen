/* PC-state VM that computes the running product of bytes:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 1;
 *   for (i = 0; i < n; i++) {
 *     r = r * (s & 0xFF);     // u8 multiplicative chain (mod 2^64)
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_byteprod64_loop_target.
 *
 * Distinct from:
 *   - vm_bytesq_sum64_loop          (per-byte squared, ADD-folded)
 *   - vm_xormul_byte_idx64_loop     (byte * counter, XOR-folded)
 *   - vm_uintadd_byte_idx64_loop    (byte * counter, ADD-folded)
 *   - vm_bytesmul_idx64_loop        (signed byte * counter, ADD-folded)
 *
 * Tests `mul i64 r, byte` chained across iterations.  Any zero byte
 * collapses the product to 0 for the rest of the loop, which the
 * lifter must not optimize away (the loop still runs to completion).
 * Inputs with no zero bytes propagate a meaningful product.
 */
#include <stdio.h>
#include <stdint.h>

enum BpVmPc {
    BP_INIT_ALL = 0,
    BP_CHECK    = 1,
    BP_BODY     = 2,
    BP_INC      = 3,
    BP_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_byteprod64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BP_INIT_ALL;

    while (1) {
        if (pc == BP_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 1ull;
            i = 0ull;
            pc = BP_CHECK;
        } else if (pc == BP_CHECK) {
            pc = (i < n) ? BP_BODY : BP_HALT;
        } else if (pc == BP_BODY) {
            r = r * (s & 0xFFull);
            s = s >> 8;
            pc = BP_INC;
        } else if (pc == BP_INC) {
            i = i + 1ull;
            pc = BP_CHECK;
        } else if (pc == BP_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byteprod64(0x0203050709020304)=%llu\n",
           (unsigned long long)vm_byteprod64_loop_target(0x0203050709020304ull));
    return 0;
}
