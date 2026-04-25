/* PC-state VM: r &= -r per iter (isolate lowest set bit):
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   while (n) {
 *     r = r & (uint64_t)(-(int64_t)r);
 *     n--;
 *   }
 *   return r;
 *
 * Lift target: vm_isolate_low_bit64_loop_target.
 *
 * Distinct from:
 *   - vm_clear_low_bit64_loop (`r & (r-1)` - clear instead of isolate)
 *   - vm_set_low_bits64_loop  (`r | (r-1)` - set bits below)
 *   - vm_negstep64_loop       (negation in two-state recurrence)
 *
 * Tests `r & -r` idiom (negation + AND).  After 1 iter r becomes
 * the single-bit mask of the lowest set bit of x; further iters
 * are idempotent (r & -r = r when r is a power of 2).
 */
#include <stdio.h>
#include <stdint.h>

enum IlVmPc {
    IL_INIT_ALL = 0,
    IL_CHECK    = 1,
    IL_BODY     = 2,
    IL_HALT     = 3,
};

__declspec(noinline)
uint64_t vm_isolate_low_bit64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    int      pc = IL_INIT_ALL;

    while (1) {
        if (pc == IL_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            pc = IL_CHECK;
        } else if (pc == IL_CHECK) {
            pc = (n > 0ull) ? IL_BODY : IL_HALT;
        } else if (pc == IL_BODY) {
            r = r & (uint64_t)(-(int64_t)r);
            n = n - 1ull;
            pc = IL_CHECK;
        } else if (pc == IL_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_isolate_low_bit64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_isolate_low_bit64_loop_target(0xCAFEBABEull));
    return 0;
}
