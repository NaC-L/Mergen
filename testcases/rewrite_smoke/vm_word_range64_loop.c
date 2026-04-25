/* PC-state VM that tracks running min and max of u16 words and returns
 * (max - min) over n = (x & 3) + 1 iterations:
 *
 *   n = (x & 3) + 1;
 *   s = x; mn = 0xFFFF; mx = 0;
 *   while (n) {
 *     uint64_t w = s & 0xFFFF;
 *     if (w > mx) mx = w;
 *     if (w < mn) mn = w;
 *     s >>= 16;
 *     n--;
 *   }
 *   return mx - mn;
 *
 * Lift target: vm_word_range64_loop_target.
 *
 * Distinct from:
 *   - vm_byterange64_loop (u8 byte stream, 8-bit stride)
 *   - vm_signed_byterange64_loop (signed bytes, raw cmp)
 *   - vm_bytemax64_loop (u8 max only)
 *
 * Tests u16 cmp-driven reductions (umax/umin) at 16-bit stride.
 * Uses n-decrement loop control (no separate i counter) to keep the
 * stateful slot count low and avoid the byteposmax-style pseudo-stack
 * init failure observed when adding a 5th slot.
 */
#include <stdio.h>
#include <stdint.h>

enum WrVmPc {
    WR_INIT_ALL = 0,
    WR_CHECK    = 1,
    WR_BODY     = 2,
    WR_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_word_range64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = WR_INIT_ALL;

    while (1) {
        if (pc == WR_INIT_ALL) {
            n  = (x & 3ull) + 1ull;
            s  = x;
            mn = 0xFFFFull;
            mx = 0ull;
            pc = WR_CHECK;
        } else if (pc == WR_CHECK) {
            pc = (n > 0ull) ? WR_BODY : WR_HALT;
        } else if (pc == WR_BODY) {
            uint64_t w = s & 0xFFFFull;
            mx = (w > mx) ? w : mx;
            mn = (w < mn) ? w : mn;
            s = s >> 16;
            n = n - 1ull;
            pc = WR_CHECK;
        } else if (pc == WR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_word_range64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_word_range64_loop_target(0xCAFEBABEull));
    return 0;
}
