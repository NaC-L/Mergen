/* PC-state VM that tracks the running min and max bytes across the
 * lower n = (x & 7) + 1 bytes and returns (max - min):
 *
 *   n = (x & 7) + 1;
 *   s = x; mn = 0xFF; mx = 0;
 *   while (n) {
 *     b = s & 0xFF;
 *     if (b > mx) mx = b;
 *     if (b < mn) mn = b;
 *     s >>= 8; n--;
 *   }
 *   return (uint64_t)(mx - mn);
 *
 * Lift target: vm_byterange64_loop_target.
 *
 * Distinct from vm_bytemax64_loop (single-reduction max only): runs
 * TWO independent cmp-driven reductions in lock-step inside the same
 * loop body, each updating its own slot, plus a final subtract.  The
 * lifter is expected to fold both branches into llvm.umax.i64 and
 * llvm.umin.i64 and then sub the final values.
 *
 * Single-byte inputs always return 0 (byte = mx = mn).
 */
#include <stdio.h>
#include <stdint.h>

enum BrVmPc {
    BR_LOAD_N    = 0,
    BR_INIT_REGS = 1,
    BR_CHECK     = 2,
    BR_BODY      = 3,
    BR_SHIFT     = 4,
    BR_DEC       = 5,
    BR_HALT      = 6,
};

__declspec(noinline)
uint64_t vm_byterange64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t s  = 0;
    uint64_t mn = 0;
    uint64_t mx = 0;
    int      pc = BR_LOAD_N;

    while (1) {
        if (pc == BR_LOAD_N) {
            n = (x & 7ull) + 1ull;
            pc = BR_INIT_REGS;
        } else if (pc == BR_INIT_REGS) {
            s  = x;
            mn = 0xFFull;
            mx = 0ull;
            pc = BR_CHECK;
        } else if (pc == BR_CHECK) {
            pc = (n > 0ull) ? BR_BODY : BR_HALT;
        } else if (pc == BR_BODY) {
            uint64_t b = s & 0xFFull;
            mx = (b > mx) ? b : mx;
            mn = (b < mn) ? b : mn;
            pc = BR_SHIFT;
        } else if (pc == BR_SHIFT) {
            s = s >> 8;
            pc = BR_DEC;
        } else if (pc == BR_DEC) {
            n = n - 1ull;
            pc = BR_CHECK;
        } else if (pc == BR_HALT) {
            return mx - mn;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_byterange64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_byterange64_loop_target(0xCAFEBABEull));
    return 0;
}
