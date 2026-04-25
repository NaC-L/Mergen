/* PC-state VM that drives a counter-bound quadratic recurrence:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) r = r*r + i;
 *   return r;   // u64, modular
 *
 * Lift target: vm_squareadd64_loop_target.
 *
 * Distinct from:
 *   - vm_geosum64_loop (multiply-by-constant + add accumulator)
 *   - vm_powmod64_loop (modexp with squaring + reduction)
 *   - vm_choosemax64_loop (pick larger of two derived options)
 *
 * Single-state u64 quadratic: r = r*r + i.  Each iteration squares
 * the accumulator and adds the loop index, exercising i64 mul on
 * mid-loop values that grow quickly mod 2^64.  Counter-driven trip
 * matches the (x & 7) + 1 recipe used by all working data-bound
 * samples.
 */
#include <stdio.h>
#include <stdint.h>

enum SqVmPc {
    SQ_INIT_ALL = 0,
    SQ_CHECK    = 1,
    SQ_BODY     = 2,
    SQ_INC      = 3,
    SQ_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_squareadd64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SQ_INIT_ALL;

    while (1) {
        if (pc == SQ_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = SQ_CHECK;
        } else if (pc == SQ_CHECK) {
            pc = (i < n) ? SQ_BODY : SQ_HALT;
        } else if (pc == SQ_BODY) {
            r = r * r + i;
            pc = SQ_INC;
        } else if (pc == SQ_INC) {
            i = i + 1ull;
            pc = SQ_CHECK;
        } else if (pc == SQ_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_squareadd64(7)=%llu\n",
           (unsigned long long)vm_squareadd64_loop_target(7ull));
    return 0;
}
