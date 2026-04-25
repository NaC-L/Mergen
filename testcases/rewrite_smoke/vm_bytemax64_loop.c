/* PC-state VM that finds the maximum byte value across the lower n bytes
 * of x where n = (x & 7) + 1.  Pure unsigned compare-driven max-update.
 *
 *   n = (x & 7) + 1;
 *   s = x; r = 0;
 *   while (n) {
 *     uint8_t b = s & 0xFF;
 *     if (b > r) r = b;
 *     s >>= 8;
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_bytemax64_loop_target.
 *
 * Distinct from:
 *   - vm_choosemax64_loop (per-iter chooses between two locally-computed
 *     options s*3+i vs s+i*i over full u64 state)
 *   - vm_smax64_loop (signed max of a derived sequence)
 *   - vm_minarray_loop (i32 min over a stack array)
 *   - vm_bytematch64 (matches a key, doesn't track a max)
 *
 * Tests u8 cmp + select-style update where the "no-update" path keeps
 * the running max unchanged.  Bytes 0x00 are special: they NEVER
 * exceed the running max, so the lifter must keep the conditional
 * write under control.
 */
#include <stdio.h>
#include <stdint.h>

enum BmVmPc {
    BM_LOAD_N    = 0,
    BM_INIT_REGS = 1,
    BM_CHECK     = 2,
    BM_BODY      = 3,
    BM_SHIFT     = 4,
    BM_DEC       = 5,
    BM_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_bytemax64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t r  = 0;
    int      pc = BM_LOAD_N;

    while (1) {
        if (pc == BM_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = BM_INIT_REGS;
        } else if (pc == BM_INIT_REGS) {
            s = x;
            r = 0ull;
            pc = BM_CHECK;
        } else if (pc == BM_CHECK) {
            pc = (n > 0ull) ? BM_BODY : BM_HALT;
        } else if (pc == BM_BODY) {
            uint64_t b = s & 0xFFull;
            r = (b > r) ? b : r;
            pc = BM_SHIFT;
        } else if (pc == BM_SHIFT) {
            s = s >> 8;
            pc = BM_DEC;
        } else if (pc == BM_DEC) {
            n = n - 1ull;
            pc = BM_CHECK;
        } else if (pc == BM_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bytemax64(0x123456789ABCDEF0)=%llu\n",
           (unsigned long long)vm_bytemax64_loop_target(0x123456789ABCDEF0ull));
    return 0;
}
