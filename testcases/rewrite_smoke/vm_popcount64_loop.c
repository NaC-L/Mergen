/* PC-state VM running Brian Kernighan's popcount on a FULL uint64_t.
 *   while (x) { x &= (x - 1); count++; }
 * Trip count = popcount(x), bounded 0..64.  Returns count as int.
 * Lift target: vm_popcount64_loop_target.
 *
 * Distinct from vm_kernighan_loop (i32 popcount) and vm_popcount_loop
 * (different style): exercises the same shape on full 64-bit state with
 * an input-derived variable trip count up to 64.
 */
#include <stdio.h>
#include <stdint.h>

enum P64VmPc {
    P64_LOAD       = 0,
    P64_LOOP_CHECK = 1,
    P64_LOOP_BODY  = 2,
    P64_HALT       = 3,
};

__declspec(noinline)
int vm_popcount64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = P64_LOAD;

    while (1) {
        if (pc == P64_LOAD) {
            state = x;
            count = 0;
            pc = P64_LOOP_CHECK;
        } else if (pc == P64_LOOP_CHECK) {
            pc = (state != 0ull) ? P64_LOOP_BODY : P64_HALT;
        } else if (pc == P64_LOOP_BODY) {
            state = state & (state - 1ull);
            count = count + 1;
            pc = P64_LOOP_CHECK;
        } else if (pc == P64_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_popcount64(0xCAFEBABE)=%d vm_popcount64(0xFFFFFFFFFFFFFFFF)=%d\n",
           vm_popcount64_loop_target(0xCAFEBABEull),
           vm_popcount64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
