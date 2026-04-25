/* PC-state VM with a doubly-nested loop on full uint64_t state.  Both
 * outer and inner bounds derive from the input.
 *   a = (x & 7) + 1;            // outer trip 1..8
 *   b = ((x >> 3) & 7) + 1;     // inner trip 1..8
 *   s = x;
 *   for i in 0..a:
 *     for j in 0..b:
 *       s = s * 31 + (i*b + j);
 *   return s;
 * Total inner iterations 1..64.  Lift target: vm_nested64_loop_target.
 *
 * Distinct from vm_nested_loop (i32 state, simpler body): exercises a
 * full i64 mul-add recurrence inside doubly-nested PC-state loops with
 * both bounds symbolic.
 */
#include <stdio.h>
#include <stdint.h>

enum NsVmPc {
    NS_LOAD       = 0,
    NS_INIT_OUTER = 1,
    NS_OUTER_CHK  = 2,
    NS_INIT_INNER = 3,
    NS_INNER_CHK  = 4,
    NS_BODY       = 5,
    NS_INNER_INC  = 6,
    NS_OUTER_INC  = 7,
    NS_HALT       = 8,
};

__declspec(noinline)
uint64_t vm_nested64_loop_target(uint64_t x) {
    int      a = 0;
    int      b = 0;
    int      i = 0;
    int      j = 0;
    uint64_t s = 0;
    int      pc = NS_LOAD;

    while (1) {
        if (pc == NS_LOAD) {
            a = (int)(x & 7ull) + 1;
            b = (int)((x >> 3) & 7ull) + 1;
            s = x;
            pc = NS_INIT_OUTER;
        } else if (pc == NS_INIT_OUTER) {
            i = 0;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_OUTER_CHK) {
            pc = (i < a) ? NS_INIT_INNER : NS_HALT;
        } else if (pc == NS_INIT_INNER) {
            j = 0;
            pc = NS_INNER_CHK;
        } else if (pc == NS_INNER_CHK) {
            pc = (j < b) ? NS_BODY : NS_OUTER_INC;
        } else if (pc == NS_BODY) {
            s = s * 31ull + (uint64_t)(i * b + j);
            pc = NS_INNER_INC;
        } else if (pc == NS_INNER_INC) {
            j = j + 1;
            pc = NS_INNER_CHK;
        } else if (pc == NS_OUTER_INC) {
            i = i + 1;
            pc = NS_OUTER_CHK;
        } else if (pc == NS_HALT) {
            return s;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("vm_nested64(0xFF)=%llu vm_nested64(0xCAFE)=%llu\n",
           (unsigned long long)vm_nested64_loop_target(0xFFull),
           (unsigned long long)vm_nested64_loop_target(0xCAFEull));
    return 0;
}
