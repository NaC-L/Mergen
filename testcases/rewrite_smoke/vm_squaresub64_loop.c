/* PC-state VM running a single-state u64 quadratic recurrence with
 * SUBTRACTIVE counter blend:
 *
 *   n = (x & 7) + 1;
 *   r = x;
 *   for (i = 0; i < n; i++) r = r*r - i;
 *   return r;
 *
 * Lift target: vm_squaresub64_loop_target.
 *
 * Distinct from:
 *   - vm_squareadd64_loop (sister: ADD i instead of SUB i)
 *
 * Quadratic recurrence with the loop counter subtracted instead of
 * added.  Tests u64 underflow behaviour inside the squaring fold.
 */
#include <stdio.h>
#include <stdint.h>

enum SqsVmPc {
    SQS_INIT_ALL = 0,
    SQS_CHECK    = 1,
    SQS_BODY     = 2,
    SQS_INC      = 3,
    SQS_HALT     = 4,
};

__declspec(noinline)
uint64_t vm_squaresub64_loop_target(uint64_t x) {
    uint64_t n  = 0;
    uint64_t r  = 0;
    uint64_t i  = 0;
    int      pc = SQS_INIT_ALL;

    while (1) {
        if (pc == SQS_INIT_ALL) {
            n = (x & 7ull) + 1ull;
            r = x;
            i = 0ull;
            pc = SQS_CHECK;
        } else if (pc == SQS_CHECK) {
            pc = (i < n) ? SQS_BODY : SQS_HALT;
        } else if (pc == SQS_BODY) {
            r = r * r - i;
            pc = SQS_INC;
        } else if (pc == SQS_INC) {
            i = i + 1ull;
            pc = SQS_CHECK;
        } else if (pc == SQS_HALT) {
            return r;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_squaresub64(0xCAFEBABE)=%llu\n",
           (unsigned long long)vm_squaresub64_loop_target(0xCAFEBABEull));
    return 0;
}
