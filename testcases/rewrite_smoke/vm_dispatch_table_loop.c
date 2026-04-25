/* PC-state VM whose successor PC comes from a stack-resident lookup table.
 * Lift target: vm_dispatch_table_loop_target.
 * Goal: cover a VM whose control flow graph is encoded as data, not code.
 * Each iteration adds the current PC to an accumulator, then advances via
 * NEXT[pc].  The starting PC is symbolic (x & 7); index 7 is the halt state
 * so the loop trip count is data-dependent and hits a different terminator
 * for each input.
 */
#include <stdio.h>

__declspec(noinline)
int vm_dispatch_table_loop_target(int x) {
    int next[8];
    int pc  = 0;
    int acc = 0;

    next[0] = 3;
    next[1] = 5;
    next[2] = 1;
    next[3] = 2;
    next[4] = 7;
    next[5] = 4;
    next[6] = 0;
    next[7] = 7;

    pc = x & 7;

    while (pc != 7) {
        acc = acc + pc;
        pc = next[pc];
    }

    return acc;
}

int main(void) {
    printf("vm_dispatch_table_loop(0)=%d vm_dispatch_table_loop(6)=%d\n",
           vm_dispatch_table_loop_target(0), vm_dispatch_table_loop_target(6));
    return 0;
}
