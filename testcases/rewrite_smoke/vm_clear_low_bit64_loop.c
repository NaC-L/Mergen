/* PC-state VM that clears the lowest set bit n times (Brian Kernighan):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r & (r - 1);   // clear lowest set bit
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_clear_low_bit64_loop_target.
 *
 * Distinct from:
 *   - vm_bit_and_self_shift_down64_loop (`r & (r >> 1)` - shift not subtract)
 *   - vm_byte_andfold64_loop (AND with byte stream)
 *
 * Tests the canonical `r & (r - 1)` clear-lowest-set-bit idiom (Brian
 * Kernighan).  Each iter removes one set bit from the bottom.  After
 * popcount(x) iters r becomes 0; for inputs with many set bits the
 * loop strips n of them.
 */
#include <stdio.h>
#include <stdint.h>

enum CkVmPc {
    CK_INIT_ALL = 0,
    CK_CHECK    = 1,
    CK_BODY     = 2,
    CK_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_clear_low_bit64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = CK_INIT_ALL;

    while (1) {
        if (pc == CK_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = CK_CHECK;
        } else if (pc == CK_CHECK) {
            pc = (n > 0ull) ? CK_BODY : CK_HALT;
        } else if (pc == CK_BODY) {
            r = r & (r - 1ull);
            n = n - 1ull;
            pc = CK_CHECK;
        } else if (pc == CK_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_clear_low_bit64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_clear_low_bit64_loop_target(0xCAFEBABEull));
    return 0;
}
