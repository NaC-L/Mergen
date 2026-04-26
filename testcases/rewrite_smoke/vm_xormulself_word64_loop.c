/* PC-state VM with self-referential multiply per iter at u16 stride:
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   for (i = 0; i < n; i++) {
 *     uint64_t w = s & 0xFFFF;
 *     r = r ^ (w * (r + 1));   // r appears in mul operand
 *     s >>= 16;
 *   }
 *   return r;
 *
 * Lift target: vm_xormulself_word64_loop_target.
 *
 * Distinct from:
 *   - vm_xormulself_byte64_loop (8-bit lane stride)
 *   - vm_xormul_word_idx64_loop (lane * counter, no self-ref)
 *
 * Tests `mul i64 word, (r+1)` where the multiplier operand is the
 * accumulator+1 (self-reference) at u16 stride.  Each iter the word
 * scales an incremented snapshot of r and XORs back.
 */
#include <stdio.h>
#include <stdint.h>

enum XmwVmPc {
    XMW_INIT_ALL = 0,
    XMW_CHECK    = 1,
    XMW_BODY     = 2,
    XMW_INC      = 3,
    XMW_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_xormulself_word64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = XMW_INIT_ALL;

    while (1) {
        if (pc == XMW_INIT_ALL) {
            n = (x & 3ull) + 1ull;
            s = x;
            r = 0ull;
            i = 0ull;
            pc = XMW_CHECK;
        } else if (pc == XMW_CHECK) {
            pc = (i < n) ? XMW_BODY : XMW_HALT;
        } else if (pc == XMW_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = r ^ (w * (r + 1ull));
            s = s >> 16;
            pc = XMW_INC;
        } else if (pc == XMW_INC) {
            i = i + 1ull;
            pc = XMW_CHECK;
        } else if (pc == XMW_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_xormulself_word64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_xormulself_word64_loop_target(0xCAFEBABEull));
    return 0;
}
