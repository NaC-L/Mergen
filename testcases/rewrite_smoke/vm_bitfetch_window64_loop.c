/* PC-state VM that reverses the lower n = (x & 7) + 1 bits of x by
 * shifting them in one at a time, fetching bit i with a DYNAMIC shift:
 *
 *   n = (x & 7) + 1;
 *   r = 0;
 *   for (i = 0; i < n; i++) {
 *     r = (r << 1) | ((x >> i) & 1);   // dynamic shift amount = i
 *   }
 *   return r;
 *
 * Lift target: vm_bitfetch_window64_loop_target.
 *
 * Distinct from:
 *   - vm_byterev_window64_loop  (8-bit window, fixed shift-by-8)
 *   - vm_nibrev_window64_loop   (4-bit window, fixed shift-by-4)
 *   - vm_bitreverse64_loop      (full 64-bit reverse, may fold)
 *
 * Tests `lshr i64 x, i` with i a loop-index variable - dynamic shift
 * amount inside dispatcher loop body.  Result is a bitwise reversal
 * of the low n bits of x.  Single-bit window with variable shift makes
 * the lifter handle non-constant shift counts iteration-by-iteration.
 */
#include <stdio.h>
#include <stdint.h>

enum BfVmPc {
    BF_INIT_ALL = 0,
    BF_CHECK    = 1,
    BF_BODY     = 2,
    BF_INC      = 3,
    BF_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_bitfetch_window64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = BF_INIT_ALL;

    while (1) {
        if (pc == BF_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = 0ull;
            i = 0ull;
            pc = BF_CHECK;
        } else if (pc == BF_CHECK) {
            pc = (i < n) ? BF_BODY : BF_HALT;
        } else if (pc == BF_BODY) {
            r = (r << 1) | ((x >> i) & 1ull);
            pc = BF_INC;
        } else if (pc == BF_INC) {
            i = i + 1ull;
            pc = BF_CHECK;
        } else if (pc == BF_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_bitfetch_window64(0xFF)=%llu\n",
           (unsigned long long)vm_bitfetch_window64_loop_target(0xFFull));
    return 0;
}
