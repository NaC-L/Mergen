/* PC-state VM that counts the run length of trailing 1-bits on full
 * uint64_t.
 *   count = 0;
 *   while (state & 1) { count++; state >>= 1; }
 *   return count;
 * Variable trip 0..64.  Lift target: vm_trailingones64_loop_target.
 *
 * Distinct from vm_cttz64_loop (counts trailing ZEROS) and
 * vm_clz64_loop (leading zeros): counts trailing ONES via shift-loop.
 * No zero special case needed because state=0 has bit 0 = 0.
 */
#include <stdio.h>
#include <stdint.h>

enum ToVmPc {
    TO_LOAD       = 0,
    TO_LOOP_CHECK = 1,
    TO_LOOP_BODY  = 2,
    TO_HALT       = 3,
};

__declspec(noinline)
int vm_trailingones64_loop_target(uint64_t x) {
    uint64_t state = 0;
    int      count = 0;
    int      pc    = TO_LOAD;

    while (1) {
        if (pc == TO_LOAD) {
            state = x;
            count = 0;
            pc = TO_LOOP_CHECK;
        } else if (pc == TO_LOOP_CHECK) {
            pc = ((state & 1ull) != 0ull) ? TO_LOOP_BODY : TO_HALT;
        } else if (pc == TO_LOOP_BODY) {
            count = count + 1;
            state = state >> 1;
            pc = TO_LOOP_CHECK;
        } else if (pc == TO_HALT) {
            return count;
        } else {
            return -1;
        }
    }
}

int main(void) {
    printf("vm_trailingones64(0xCAFF)=%d vm_trailingones64(max)=%d\n",
           vm_trailingones64_loop_target(0xCAFFull),
           vm_trailingones64_loop_target(0xFFFFFFFFFFFFFFFFull));
    return 0;
}
