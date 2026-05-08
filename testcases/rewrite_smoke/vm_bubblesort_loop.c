/* PC-state VM running a single bubble pass with conditional two-slot swap.
 *   Previously tripped BB budget exceeded because the lifter enumerated
 *   the swap-vs-no-swap path across every iteration (2^N paths).
 *
 * Processes adjacent pairs of nibbles from input x, swapping if out of order.
 * Trip count: n = (x & 0x7) + 1  (1..8 pairs).
 * Returns packed result of one bubble pass.
 * Lift target: vm_bubblesort_loop_target.
 */
#include <stdio.h>
#include <stdint.h>

enum BsVmPc {
    BS_LOAD       = 0,
    BS_LOOP_CHECK = 1,
    BS_COMPARE    = 2,
    BS_SWAP       = 3,
    BS_NO_SWAP    = 4,
    BS_LOOP_INC   = 5,
    BS_HALT       = 6,
};

__declspec(noinline)
uint64_t vm_bubblesort_loop_target(uint64_t x) {
    int      pc   = BS_LOAD;
    int      idx  = 0;
    int      n    = 0;
    uint64_t data = 0;
    uint64_t a    = 0;
    uint64_t b    = 0;

    while (1) {
        if (pc == BS_LOAD) {
            data = x;
            n    = (int)(x & 0x7ull) + 1;
            idx  = 0;
            pc   = BS_LOOP_CHECK;
        } else if (pc == BS_LOOP_CHECK) {
            pc = (idx < n) ? BS_COMPARE : BS_HALT;
        } else if (pc == BS_COMPARE) {
            a = (data >> (idx * 4)) & 0xF;
            b = (data >> ((idx + 1) * 4)) & 0xF;
            pc = (a > b) ? BS_SWAP : BS_NO_SWAP;
        } else if (pc == BS_SWAP) {
            /* Clear both nibble positions and write swapped values */
            uint64_t mask = ~(0xFull << (idx * 4)) & ~(0xFull << ((idx + 1) * 4));
            data = (data & mask) | (b << (idx * 4)) | (a << ((idx + 1) * 4));
            pc = BS_LOOP_INC;
        } else if (pc == BS_NO_SWAP) {
            /* no swap needed */
            pc = BS_LOOP_INC;
        } else if (pc == BS_LOOP_INC) {
            idx = idx + 1;
            pc  = BS_LOOP_CHECK;
        } else if (pc == BS_HALT) {
            return data;
        } else {
            return 0xFFFFFFFFFFFFFFFFull;
        }
    }
}

int main(void) {
    printf("bs(0x4321)=0x%llx bs(0x1234)=0x%llx\n",
           (unsigned long long)vm_bubblesort_loop_target(0x4321ull),
           (unsigned long long)vm_bubblesort_loop_target(0x1234ull));
    return 0;
}
