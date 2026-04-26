/* PC-state VM that finds the maximum u16 word value across the lower n
 * words of x where n = (x & 3) + 1.  Pure unsigned compare-driven
 * max-update.
 *
 *   n = (x & 3) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint16_t w = s & 0xFFFF;
 *     if (w > r) r = w;
 *     s >>= 16;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_wordmax64_loop_target.
 *
 * Distinct from:
 *   - vm_bytemax64_loop (8-bit stride)
 *   - vm_word_addchain64_loop (sum, no max)
 *
 * Tests u16 cmp + select-style update where the "no-update" path keeps
 * the running max unchanged at u16 stride.
 */
#include <stdio.h>
#include <stdint.h>

enum WmVmPc {
    WM_LOAD_N    = 0,
    WM_INIT_REGS = 1,
    WM_CHECK     = 2,
    WM_BODY      = 3,
    WM_SHIFT     = 4,
    WM_DEC       = 5,
    WM_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_wordmax64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = WM_LOAD_N;

    while (1) {
        if (pc == WM_LOAD_N) {
            n = (x & 3ull) + 1ull;
            pc = WM_INIT_REGS;
        } else if (pc == WM_INIT_REGS) {
            s = x;
            r = 0ull;
            pc = WM_CHECK;
        } else if (pc == WM_CHECK) {
            pc = (n > 0ull) ? WM_BODY : WM_HALT;
        } else if (pc == WM_BODY) {
            uint64_t w = s & 0xFFFFull;
            r = (w > r) ? w : r;
            pc = WM_SHIFT;
        } else if (pc == WM_SHIFT) {
            s = s >> 16;
            pc = WM_DEC;
        } else if (pc == WM_DEC) {
            n = n - 1ull;
            pc = WM_CHECK;
        } else if (pc == WM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_wordmax64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_wordmax64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
