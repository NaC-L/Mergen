/* PC-state VM with self-referential multiply per iter:
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t b = s & 0xFF;
 *     r = r ^ (b * (r + 1));   // r appears in mul operand
 *     s >>= 8;
 *   }
 *   return r;
 *
 * Lift target: vm_xormulself_byte64_loop_target.
 *
 * Distinct from:
 *   - vm_xormul_byte_idx64_loop  (byte * counter, XOR-folded)
 *   - vm_bytesmul_idx64_loop     (sext byte * counter, ADD)
 *   - vm_squareadd64_loop        (r*r self-multiply on full state)
 *
 * Tests `mul i64 byte, (r+1)` where the multiplier operand is the
 * accumulator+1 (self-reference).  Each iter the byte scales an
 * incremented snapshot of r and XORs back.  Reaches 200-sample
 * milestone.
 */
#include <stdio.h>
#include <stdint.h>

enum XmVmPc {
    XM_INIT_ALL = 0,
    XM_CHECK    = 1,
    XM_BODY     = 2,
    XM_INC      = 3,
    XM_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulself_byte64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XM_INIT_ALL;

    while (1) {
        if (pc == XM_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XM_CHECK;
        } else if (pc == XM_CHECK) {
            pc = (i < n) ? XM_BODY : XM_HALT;
        } else if (pc == XM_BODY) {
            uint64_t b = s & 0xFFull;
            r = r ^ (b * (r + 1ull));
            s = s >> 8;
            pc = XM_INC;
        } else if (pc == XM_INC) {
            i = i + 1ull;
            pc = XM_CHECK;
        } else if (pc == XM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulself_byte64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormulself_byte64_loop_target(0xCAFEBABEull));
    return 0;
}
